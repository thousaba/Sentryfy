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

const PORT = process.env.PORT || 3000;

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

// app.listen yerine httpServer.listen
httpServer.listen(PORT, () => {
  console.log(`Sentryfy Backend ayakta! Port: ${PORT} 🛡️`);
});