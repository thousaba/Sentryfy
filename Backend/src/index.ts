import express, { type Request, type Response } from 'express';
import { createServer } from 'http';
import { Server } from 'socket.io';
import dotenv from 'dotenv';
import cors from 'cors';
import axios from 'axios';
import https from 'https';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';
import { startPoller, type SplunkAlert } from './splunk-poller.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
dotenv.config({ path: join(__dirname, '../.env') });

const TELEGRAM_TOKEN   = process.env.TELEGRAM_TOKEN;
const TELEGRAM_CHAT_ID = process.env.TELEGRAM_CHAT_ID;
const WAZUH_API_URL    = process.env.WAZUH_API_URL  ?? 'https://localhost:55000';
const WAZUH_API_USER   = process.env.WAZUH_API_USER ?? 'wazuh';
const WAZUH_API_PASS   = process.env.WAZUH_API_PASS ?? 'wazuh';

// ─── Wazuh REST client ────────────────────────────────────────────────────────

const wazuhHttp = axios.create({
  baseURL:    WAZUH_API_URL,
  httpsAgent: new https.Agent({ rejectUnauthorized: false }),
});

// ─── Wazuh API: JWT ───────────────────────────────────────────────────────────

let _wazuhToken: string | null = null;
let _tokenExpiry = 0;

async function getWazuhToken(): Promise<string> {
  if (_wazuhToken && Date.now() < _tokenExpiry) return _wazuhToken;
  const credentials = Buffer.from(`${WAZUH_API_USER}:${WAZUH_API_PASS}`).toString('base64');
  const res = await wazuhHttp.post('/security/user/authenticate', null, {
    headers: { Authorization: `Basic ${credentials}` },
  });
  _wazuhToken  = res.data.data.token as string;
  _tokenExpiry = Date.now() + 14 * 60 * 1000;
  return _wazuhToken;
}

async function resolveAgentId(hostname: string): Promise<string | null> {
  const token = await getWazuhToken();
  const res = await wazuhHttp.get('/agents', {
    headers: { Authorization: `Bearer ${token}` },
    params:  { name: hostname, limit: 1 },
  });
  const items = res.data?.data?.affected_items as Array<{ id: string }> | undefined;
  return items && items.length > 0 ? items[0]!.id : null;
}

async function triggerActiveResponse(
  agentId: string,
  command: string,
  srcIp:   string | undefined,
  meta:    object,
): Promise<void> {
  const token = await getWazuhToken();
  await wazuhHttp.put(
    '/active-response',
    {
      command,
      alert: {
        rule: { description: 'Sentryfy: Splunk-triggered active response', level: 12 },
        data: { srcip: srcIp ?? '', extra: meta },
      },
    },
    {
      headers: { Authorization: `Bearer ${token}` },
      params:  { agents_list: agentId },
    },
  );
  console.log(`[AR] ✅ Active Response — agent: ${agentId} | cmd: ${command} | src: ${srcIp ?? '-'}`);
}

// ─── Telegram ─────────────────────────────────────────────────────────────────

const esc = (v: unknown) =>
  String(v).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');

async function sendTelegram(html: string): Promise<void> {
  let text = html.length > 4000 ? html.substring(0, 3900) + '\n\n...(kısaltıldı)' : html;
  await axios.post(`https://api.telegram.org/bot${TELEGRAM_TOKEN}/sendMessage`, {
    chat_id:    TELEGRAM_CHAT_ID,
    text,
    parse_mode: 'HTML',
  });
}

// ─── Express + Socket.IO ──────────────────────────────────────────────────────

const app        = express();
const httpServer = createServer(app);
const io         = new Server(httpServer, { cors: { origin: '*' } });

app.use(cors());
app.use(express.json());

const PORT = Number(process.env.PORT) || 3000;

io.on('connection', socket => {
  console.log('🔌 Frontend bağlandı:', socket.id);
  socket.on('disconnect', () => console.log('❌ Frontend ayrıldı:', socket.id));
});

// ─── Webhook: Wazuh ───────────────────────────────────────────────────────────

app.post('/api/webhook/wazuh', async (req: Request, res: Response) => {
  const alertData = req.body;

  if ((alertData?.rule?.level ?? 0) >= 10) {
    const rawIp   = alertData?.data?.win?.eventdata?.ipAddress;
    const agentIp = alertData?.agent?.ip;
    const ip =
      !rawIp || rawIp === '-' || rawIp === '::1' || rawIp === '0.0.0.0'
        ? agentIp ? `Yerel (${agentIp})` : 'Bilinmiyor'
        : rawIp;

    io.emit('new-alert', { ...alertData, resolvedIp: ip });

    const msg =
      `🚨 *SENTRYFY ALARM* 🚨\n\n` +
      `*Kural:* ${alertData.rule.description}\n` +
      `*Seviye:* ${alertData.rule.level}\n` +
      `*Ajan:* ${alertData.agent.name}\n` +
      `*IP:* ${ip}\n` +
      `*Zaman:* ${alertData.timestamp}`;

    try {
      await axios.post(`https://api.telegram.org/bot${TELEGRAM_TOKEN}/sendMessage`, {
        chat_id: TELEGRAM_CHAT_ID, text: msg, parse_mode: 'Markdown',
      });
    } catch (err: any) {
      console.error('❌ Telegram (Wazuh):', err?.response?.data ?? err.message);
    }
  }

  res.status(200).send('ok');
});

// ─── Splunk Alert Handler (poller callback) ────────────────────────────────────

async function onSplunkAlert(alert: SplunkAlert): Promise<void> {
  const { rule, results, firedAt } = alert;
  const first   = results[0]!;
  const computer = first['ComputerName'] ?? first['host'] ?? 'Bilinmiyor';
  const user     = first['User'] ?? first['SubjectUserName'] ?? '-';
  const srcIp    = first['IpAddress'] ?? first['src_ip'] ?? first['SourceIp'] ?? undefined;

  console.log(`[Alert] 🚨 ${rule.name} — ${results.length} hit(s) — ${computer}`);

  // Frontend emit
  io.emit('new-alert', {
    timestamp: firedAt,
    source:    'splunk-poll',
    rule:      { id: rule.id, level: rule.severity, description: rule.name },
    agent:     { id: 'splunk', name: computer, ip: computer },
    raw:       first,
  });

  // Telegram
  let msg = `🚨 <b>SPLUNK ALARM</b> 🚨\n\n`;
  msg += `<b>Kural:</b> ${esc(rule.name)}\n`;
  msg += `<b>MITRE:</b> <code>${esc(rule.mitre)}</code>\n`;
  msg += `<b>Bilgisayar:</b> ${esc(computer)}\n`;
  msg += `<b>Kullanıcı:</b> ${esc(user)}\n`;
  if (srcIp) msg += `<b>Kaynak IP:</b> <code>${esc(srcIp)}</code>\n`;
  msg += `<b>Hit sayısı:</b> ${results.length}\n`;
  msg += `<b>Zaman:</b> ${esc(firedAt)}`;

  try {
    await sendTelegram(msg);
    console.log(`[Alert] ✅ Telegram gönderildi — ${rule.id}`);
  } catch (err: any) {
    console.error('[Alert] ❌ Telegram:', err?.response?.data ?? err.message);
  }

  // Active Response — ar_command tanımlıysa veya severity ≥ 12 ise
  const arCommand = rule.ar_command ?? (rule.severity >= 12 ? 'firewall-drop' : undefined);
  if (arCommand && computer !== 'Bilinmiyor') {
    try {
      const agentId = await resolveAgentId(computer);
      if (agentId) {
        await triggerActiveResponse(agentId, arCommand, srcIp, { rule: rule.id, hits: results.length });
      } else {
        console.warn(`[AR] ⚠️  Agent bulunamadı: ${computer}`);
      }
    } catch (err: any) {
      console.error('[AR] ❌ Active Response:', err?.response?.data ?? err.message);
    }
  }
}

// ─── Start ────────────────────────────────────────────────────────────────────

httpServer.listen(PORT, '0.0.0.0', () => {
  console.log(`Sentryfy Backend ayakta! Port: ${PORT} 🛡️`);
  startPoller(onSplunkAlert);
});
