# Sentryfy — Real-Time SIEM Dashboard

An open-source SIEM monitoring project that aggregates alerts from multiple security platforms into a single dashboard and delivers instant notifications via Telegram.

---

## Overview

Sentryfy captures alerts from security platforms such as **Wazuh** and **Splunk** via webhooks, processes them through a Node.js backend, and reflects them on a live React-based dashboard. Through Telegram Bot integration, critical events are instantly delivered as mobile notifications.

The project is under active development — new SIEM platforms, event types, and rules are added regularly.

---

## Architecture

```
SIEM Platforms
 ├── Wazuh Manager  ──┐
 └── Splunk Enterprise ┘
           │
     Webhook (POST)
           │
     Node.js Backend  (Express + Socket.IO)
      ├── React Dashboard  (live, Socket.IO)
      └── Telegram Bot     (instant notifications)
```

---

## Tech Stack

| Layer | Technology |
|---|---|
| Backend | Node.js, Express, TypeScript, Socket.IO |
| Frontend | React, TypeScript, Vite, Socket.IO Client |
| SIEM | Wazuh, Splunk Enterprise |
| Notifications | Telegram Bot API |
| Tunnel | ngrok |

---

## Folder Structure

```
Sentryfy/
├── Backend/          # Express + Socket.IO server, webhook endpoints
│   └── src/
│       └── index.ts
├── Dashboard/        # React dashboard (live alert display)
│   └── src/
├── RULES/            # Rule and query documentation
│   ├── Wazuh-Rules.md
│   └── Splunk-Rules.md
└── screenshots/      # Screenshots
```

---

## Setup

### Requirements

- Node.js 18+
- A running Wazuh or Splunk installation
- Telegram Bot Token and Chat ID

### Backend

```bash
cd Backend
npm install
cp .env.example .env   # Enter TELEGRAM_TOKEN and TELEGRAM_CHAT_ID
npm run dev
```

### Dashboard

```bash
cd Dashboard
npm install
npm run dev
```

### External Access (for Wazuh webhook)

```bash
ngrok http 3000
```

Enter the ngrok URL into the Wazuh `ossec.conf` integration block or the Splunk Alert webhook setting.

---

## Webhook Endpoints

| Platform | Endpoint |
|---|---|
| Wazuh | `POST /api/webhook/wazuh` |
| Splunk | `POST /api/webhook/splunk` |

---

## Rule Documentation

See the `RULES/` folder for platform-specific rule and query documentation.

---

