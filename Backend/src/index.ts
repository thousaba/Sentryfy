import express, { type Request, type Response } from 'express';
import { createServer } from 'http';
import { Server } from 'socket.io';
import dotenv from 'dotenv';
import cors from 'cors';
import axios from 'axios';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';

const __dirname = dirname(fileURLToPath(import.meta.url));
dotenv.config({ path: join(__dirname, '../.env') });

const TELEGRAM_TOKEN = process.env.TELEGRAM_TOKEN;
const TELEGRAM_CHAT_ID = process.env.TELEGRAM_CHAT_ID;

const app = express();
const httpServer = createServer(app); // Express'i HTTP server'a sardık
const io = new Server(httpServer, {
  cors: { origin: '*' }
});

app.use(cors());
app.use(express.json());

const PORT = Number(process.env.PORT) || 3000;

// Socket.IO bağlantı log'u
io.on('connection', (socket) => {
  console.log('🔌 Frontend bağlandı:', socket.id);
  socket.on('disconnect', () => {
    console.log('❌ Frontend ayrıldı:', socket.id);
  });
});

// Wazuh webhook
app.post('/api/webhook/wazuh', async (req: Request, res: Response) => {
  const alertData = req.body;
  //console.log("📦 Ham veri:", JSON.stringify(alertData, null, 2));

  if (alertData?.rule?.level >= 10) {

    // IP çözümleme
    const rawIp = alertData?.data?.win?.eventdata?.ipAddress;
    const agentIp = alertData?.agent?.ip;

    let ip: string;
    if (!rawIp || rawIp === '-' || rawIp === '::1' || rawIp === '0.0.0.0') {
      ip = agentIp ? `Yerel (${agentIp})` : 'Bilinmiyor';
    } else {
      ip = rawIp;
    }

    // Frontend'e emit
    io.emit('new-alert', { ...alertData, resolvedIp: ip });
    console.log('📡 Frontend\'e emit edildi');

    const message = `🚨 *SENTRYFY ALARM* 🚨\n\n` +
                    `*Kural:* ${alertData.rule.description}\n` +
                    `*Seviye:* ${alertData.rule.level}\n` +
                    `*Ajan:* ${alertData.agent.name}\n` +
                    `*IP:* ${ip}\n` +
                    `*Zaman:* ${alertData.timestamp}`;

    try {
      await axios.post(`https://api.telegram.org/bot${TELEGRAM_TOKEN}/sendMessage`, {
        chat_id: TELEGRAM_CHAT_ID,
        text: message,
        parse_mode: 'Markdown'
      });
      console.log('✅ Telegram\'a uçuruldu!');
    } catch (error: any) {
      console.error('❌ Telegram hatası:', error?.response?.data || error.message);
    }
  }

  res.status(200).send('Log alındı 🍻');
});


app.post('/api/webhook/splunk', async (req: Request, res: Response) => {
  try {
    const alertData = req.body;
    const result = alertData.result ?? {};
    const searchName = alertData.search_name ?? 'Splunk Alert';
    
    console.log('📦 Splunk webhook payload:', JSON.stringify(alertData, null, 2));

    const computer = result.ComputerName ?? result.host ?? 'Bilinmiyor';
    const user = result.User ?? result.user ?? result.SubjectUserName ?? 'Bilinmiyor';
    const time = result._time ?? new Date().toISOString();

    const metaFields = ['_time', '_raw', 'host', 'source', 'sourcetype', 'index',
                        'ComputerName', 'User', 'SubjectUserName'];
    const customFields = Object.entries(result)
      .filter(([key]) => !metaFields.includes(key) && !key.startsWith('_'))
      .filter(([, value]) => value !== null && value !== undefined && value !== '')
      .slice(0, 5);

    // Frontend emit
    const normalizedAlert = {
      timestamp: time,
      source: 'splunk',
      rule: { id: 'splunk', level: 10, description: searchName },
      agent: { id: 'splunk', name: computer, ip: computer },
      raw: result,
    };
    io.emit('new-alert', normalizedAlert);
    console.log("📡 Splunk alarmı frontend'e emit edildi");

    // HTML escape helper
    const esc = (text: any) => String(text)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;');

    // Telegram mesajı (HTML format)
    let message = `🚨 <b>SPLUNK ALARM</b> 🚨\n\n`;
    message += `<b>Kural:</b> ${esc(searchName)}\n`;
    message += `<b>Bilgisayar:</b> ${esc(computer)}\n`;
    message += `<b>Kullanıcı:</b> ${esc(user)}\n`;

    for (const [key, value] of customFields) {
      let valStr = String(value);
      if (valStr.length > 300) valStr = valStr.substring(0, 300) + '...';
      message += `<b>${esc(key)}:</b> <code>${esc(valStr)}</code>\n`;
    }

    message += `\n<b>Zaman:</b> ${esc(time)}`;

    // 4096 char limit koruması
    if (message.length > 4000) {
      message = message.substring(0, 3900) + '\n\n... (mesaj kısaltıldı)';
    }

    await axios.post(
      `https://api.telegram.org/bot${TELEGRAM_TOKEN}/sendMessage`,
      {
        chat_id: TELEGRAM_CHAT_ID,
        text: message,
        parse_mode: 'HTML',
      }
    );
    console.log("✅ Splunk alarmı Telegram'a gönderildi!");
    
    res.status(200).json({ received: true });
  } catch (error: any) {
    console.error('❌ Webhook hatası:', error?.response?.data || error.message);
    res.status(500).json({ error: 'Webhook processing failed' });
  }
});


// app.listen yerine httpServer.listen
httpServer.listen(PORT, '0.0.0.0', () => {
  console.log(`Sentryfy Backend ayakta! Port: ${PORT} 🛡️`);
});
