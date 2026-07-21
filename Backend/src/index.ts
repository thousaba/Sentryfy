import express, { type Request, type Response } from 'express';
import { createServer } from 'http';
import { Server } from 'socket.io';
import dotenv from 'dotenv';
import cors from 'cors';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';

const __dirname = dirname(fileURLToPath(import.meta.url));
dotenv.config({ path: join(__dirname, '../.env') });

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


type Severity = 'critical' | 'high' | 'medium' | 'low';

function severityFor(totalRisk: number): Severity {
  if (totalRisk >= 80) return 'critical';
  if (totalRisk >= 50) return 'high';
  if (totalRisk >= 30) return 'medium';
  return 'low';
}


function toList(value: unknown): string[] {
  if (Array.isArray(value)) return value.map(String);
  if (typeof value === 'string' && value.length > 0) return value.split('\n');
  return [];
}

app.post('/api/webhook/splunk', (req: Request, res: Response) => {
  const body   = req.body ?? {};
  const result = body.result ?? {};

  console.log('[Splunk Webhook] RAW BODY:', JSON.stringify(body));

  const riskObject     = String(result['risk_object'] ?? 'Bilinmiyor');
  const totalRisk      = Number(result['total_risk']) || 0;
  const detectionCount = Number(result['detection_count']) || 0;
  const techniqueCount = Number(result['technique_count']) || 0;
  const detections     = toList(result['detections']);
  const techniques     = toList(result['techniques']);

  console.log(`[Splunk Webhook] 🚨 ${riskObject} — risk ${totalRisk}`);

  io.emit('new-alert', {
    id:        `${riskObject}-${Date.now()}`,
    timestamp: new Date().toISOString(),
    riskObject,
    totalRisk,
    severity:  severityFor(totalRisk),
    detectionCount,
    detections,
    techniqueCount,
    techniques,
  });

  res.status(200).send('ok');
});


httpServer.listen(PORT, '0.0.0.0', () => {
  console.log(`Sentryfy Backend ayakta! Port: ${PORT} 🛡️`);
});
