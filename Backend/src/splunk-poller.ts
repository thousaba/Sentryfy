import axios from 'axios';
import https from 'https';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { RULES, type SplunkRule } from './rules.js';

const REPO_ROOT = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  '../../'
);

function loadSpl(splFile: string): string {
  const fullPath = path.join(REPO_ROOT, splFile);
  return fs.readFileSync(fullPath, 'utf-8').trim();
}

// ─── Splunk REST client ────────────────────────────────────────────────────────

const splunkHttp = axios.create({
  baseURL:    process.env.SPLUNK_URL  ?? 'https://localhost:8089',
  httpsAgent: new https.Agent({ rejectUnauthorized: false }),
  auth: {
    username: process.env.SPLUNK_USER ?? 'admin',
    password: process.env.SPLUNK_PASS ?? '',
  },
});

// ─── Search helpers ────────────────────────────────────────────────────────────

async function createJob(spl: string, earliestTime: string): Promise<string> {
  const res = await splunkHttp.post(
    '/services/search/jobs',
    new URLSearchParams({
      search:        `search ${spl}`,
      earliest_time: earliestTime,
      latest_time:   'now',
      output_mode:   'json',
    }),
  );
  return res.data.sid as string;
}

async function waitForJob(sid: string, timeoutMs = 20_000): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    await sleep(1_000);
    const res = await splunkHttp.get(`/services/search/jobs/${sid}`, {
      params: { output_mode: 'json' },
    });
    if (res.data.entry?.[0]?.content?.isDone) return;
  }
  // timeout — job muhtemelen sonuç üretmedi, devam et
}

async function getResults(sid: string): Promise<Record<string, string>[]> {
  const res = await splunkHttp.get(`/services/search/jobs/${sid}/results`, {
    params: { output_mode: 'json', count: 50 },
  });
  return (res.data.results ?? []) as Record<string, string>[];
}

async function deleteJob(sid: string): Promise<void> {
  await splunkHttp.delete(`/services/search/jobs/${sid}`).catch(() => {/* best-effort */});
}

function sleep(ms: number) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

// ─── Dedup — son görülen _time her kural için saklanır ────────────────────────

// ISO8601 → epoch saniye (Splunk _time formatı)
function toEpoch(t: string): number {
  return Math.floor(new Date(t).getTime() / 1000);
}

const lastSeen = new Map<string, number>(); // ruleId → epoch saniye

function buildEarliestTime(ruleId: string, lookbackSeconds: number): string {
  const epoch = lastSeen.get(ruleId);
  // Bir önceki poll'da son görülen event'ten 1sn sonrasından başla
  return epoch ? `${epoch + 1}` : `-${lookbackSeconds}s`;
}

function updateLastSeen(ruleId: string, results: Record<string, string>[]): void {
  const times = results
    .map(r => toEpoch(r['_time'] ?? ''))
    .filter(t => !isNaN(t));
  if (times.length === 0) return;
  const maxTime = Math.max(...times);
  const prev = lastSeen.get(ruleId) ?? 0;
  if (maxTime > prev) lastSeen.set(ruleId, maxTime);
}

// ─── Alert callback tip tanımı ─────────────────────────────────────────────────

export interface SplunkAlert {
  rule:    SplunkRule;
  results: Record<string, string>[];
  firedAt: string;
}

export type AlertHandler = (alert: SplunkAlert) => Promise<void>;

// ─── Tek bir kural için poll döngüsü ──────────────────────────────────────────

async function pollRule(
  rule:           SplunkRule,
  lookbackSeconds: number,
  onAlert:        AlertHandler,
): Promise<void> {
  const earliestTime = buildEarliestTime(rule.id, lookbackSeconds);
  let sid: string | null = null;

  try {
    sid = await createJob(loadSpl(rule.splFile), earliestTime);
    await waitForJob(sid);
    const results = await getResults(sid);

    if (results.length > 0) {
      updateLastSeen(rule.id, results);
      await onAlert({ rule, results, firedAt: new Date().toISOString() });
    }
  } catch (err: any) {
    console.error(`[Poller] ❌ ${rule.id}:`, err?.response?.data?.messages?.[0]?.text ?? err.message);
  } finally {
    if (sid) await deleteJob(sid);
  }
}

// ─── Ana polling döngüsü ───────────────────────────────────────────────────────

export function startPoller(onAlert: AlertHandler): void {
  const intervalSeconds = Number(process.env.SPLUNK_POLL_INTERVAL_SECONDS ?? 60);

  // Başlangıçta lookback = 2 × interval (restart'ta kaçırmamak için)
  const lookbackSeconds = intervalSeconds * 2;

  const tick = async () => {
    console.log(`[Poller] 🔄 Poll başladı — ${new Date().toISOString()}`);
    // Kuralları paralel çalıştır
    await Promise.allSettled(
      RULES.map(rule => pollRule(rule, lookbackSeconds, onAlert)),
    );
    console.log(`[Poller] ✅ Poll tamamlandı`);
  };

  // İlk çalıştırma hemen
  tick();
  setInterval(tick, intervalSeconds * 1_000);

  console.log(`[Poller] 🚀 Splunk polling başlatıldı — interval: ${intervalSeconds}s`);
}
