# Sentryfy — Gerçek Zamanlı SIEM Dashboard

Birden fazla güvenlik platformundan gelen alertleri tek bir dashboard'da toplayan, Telegram üzerinden anlık bildirim gönderen açık kaynaklı bir SIEM izleme projesi.

---

## Genel Bakış

Sentryfy; **Wazuh** ve **Splunk** gibi güvenlik platformlarından gelen alertleri webhook aracılığıyla yakalar, Node.js backend üzerinden işler ve React tabanlı canlı bir dashboard'a yansıtır. Aynı zamanda Telegram Bot entegrasyonu sayesinde önemli olaylar anında mobil bildirime dönüşür.

Proje sürekli geliştirilmekte olup yeni SIEM platformları, olay türleri ve kurallar düzenli olarak eklenmektedir.

---

## Mimari

```
SIEM Platformları
 ├── Wazuh Manager  ──┐
 └── Splunk Enterprise ┘
           │
     Webhook (POST)
           │
     Node.js Backend  (Express + Socket.IO)
      ├── React Dashboard  (canlı, Socket.IO)
      └── Telegram Bot     (anlık bildirim)
```

---

## Teknoloji Yığını

| Katman | Teknoloji |
|---|---|
| Backend | Node.js, Express, TypeScript, Socket.IO |
| Frontend | React, TypeScript, Vite, Socket.IO Client |
| SIEM | Wazuh, Splunk Enterprise |
| Bildirim | Telegram Bot API |
| Tünel | ngrok |

---

## Klasör Yapısı

```
Sentryfy/
├── Backend/          # Express + Socket.IO sunucusu, webhook endpoint'leri
│   └── src/
│       └── index.ts
├── Dashboard/        # React dashboard (canlı alert görüntüleme)
│   └── src/
├── RULES/            # Kural ve sorgu dokümantasyonu
│   ├── Wazuh-Rules.md
│   └── Splunk-Rules.md
└── screenshots/      # Ekran görüntüleri
```

---

## Kurulum

### Gereksinimler

- Node.js 18+
- Çalışan bir Wazuh veya Splunk kurulumu
- Telegram Bot Token ve Chat ID

### Backend

```bash
cd Backend
npm install
cp .env.example .env   # TELEGRAM_TOKEN ve TELEGRAM_CHAT_ID gir
npm run dev
```

### Dashboard

```bash
cd Dashboard
npm install
npm run dev
```

### Dış Erişim (Wazuh webhook için)

```bash
ngrok http 3000
```

Ngrok URL'ini Wazuh `ossec.conf` integration bloğuna veya Splunk Alert webhook ayarına gir.

---

## Webhook Endpoint'leri

| Platform | Endpoint |
|---|---|
| Wazuh | `POST /api/webhook/wazuh` |
| Splunk | `POST /api/webhook/splunk` |

---

## Kural Dokümantasyonu

Platform bazlı kural ve sorgu açıklamaları için `RULES/` klasörüne bakınız.

---

