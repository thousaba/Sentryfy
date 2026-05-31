# Sentryfy — Real-Time SIEM Dashboard

An open-source detection engineering project that collects Windows telemetry via Sysmon, runs SPL-based detection rules against Splunk, and delivers real-time alerts through a live React dashboard, Telegram notifications, and automated Wazuh Active Response.

---

## Overview

Sentryfy's backend continuously polls Splunk's REST API, evaluates detection rules mapped to the MITRE ATT&CK framework, and acts on results — no Splunk Enterprise license required. When a rule fires, the backend simultaneously updates the live dashboard, sends a Telegram notification, and (for critical severity) calls the Wazuh API to trigger an automated active response on the affected endpoint.

The project is under active development — new detection rules and MITRE technique coverage are added regularly.

---

## MITRE ATT&CK Coverage Analysis

Sentryfy's detection rules are mapped against the [MITRE ATT&CK Enterprise framework](https://attack.mitre.org/). The coverage document tracks which tactics and techniques are currently defended, details the detection logic behind each rule, and outlines the prioritized roadmap for closing coverage gaps.

→ [View Coverage Analysis](./docs/MITRE-Coverage-Analysis.md)

---

## Architecture

```
Windows Agent
  └── Sysmon
        │
        ├──► Wazuh Manager ──── Webhook (POST) ──────────────────────┐
        │                                                             │
        └──► Splunk (index=windows)                                  ▼
                  ▲                                        Node.js Backend
                  │  REST API polling (60s)               (Express + Socket.IO)
                  └──────────────────────────────────────────────────┤
                                                                      │
                                          ┌───────────────────────────┼──────────────────────┐
                                          ▼                           ▼                      ▼
                                   React Dashboard            Telegram Bot           Wazuh API
                                   (live alerts)              (notifications)    (Active Response)
                                                                                       │
                                                                              Windows Agent
                                                                              firewall-drop / kill-process
```

**Alert flow (Splunk path):**
1. Sysmon generates telemetry → ingested into Splunk (`index=windows`)
2. Backend polls Splunk REST API every 60 seconds with SPL detection rules
3. On a hit → emit to dashboard + send Telegram notification
4. If severity ≥ 12 → resolve Wazuh agent ID by hostname → trigger Active Response

---

## Tech Stack

| Layer | Technology |
|---|---|
| Backend | Node.js, Express, TypeScript, Socket.IO |
| Frontend | React, TypeScript, Vite, Socket.IO Client |
| Telemetry | Sysmon (SwiftOnSecurity baseline) |
| SIEM | Splunk Free (REST API polling) |
| Endpoint Security | Wazuh (webhook + Active Response API) |
| Notifications | Telegram Bot API |
| Tunnel | ngrok (Wazuh webhook exposure) |

---

## Folder Structure

```
Sentryfy/
├── Backend/
│   └── src/
│       ├── index.ts          # Express server, Wazuh webhook, alert handler
│       ├── splunk-poller.ts  # Splunk REST API polling engine
│       └── rules.ts          # Detection rule registry (metadata + file paths)
├── Dashboard/
│   └── src/                  # React live alert dashboard
├── Rules/
│   ├── Splunk-SPL/           # SPL detection queries (one file per technique)
│   │   ├── Initial-Access/
│   │   ├── Execution/
│   │   ├── Persistence/
│   │   ├── Privilege-Escalation/
│   │   ├── Defense-Evasion/
│   │   └── Credential-Access/
│   └── Sigma/                # Sigma rules (convertible to any SIEM)
├── docs/                     # Technique documentation + MITRE coverage analysis
└── screenshots/
```

---

## Setup

### Requirements

- Node.js 18+
- Splunk (Free license is sufficient) with Sysmon/Windows logs ingested
- Wazuh Manager + Agent (for Active Response)
- Telegram Bot Token and Chat ID

### Backend

```bash
cd Backend
npm install
cp .env.example .env
```

Edit `.env`:

```env
# Telegram
TELEGRAM_TOKEN=your_bot_token
TELEGRAM_CHAT_ID=your_chat_id

# Wazuh API (Manager)
WAZUH_API_URL=https://<wazuh-manager-ip>:55000
WAZUH_API_USER=admin
WAZUH_API_PASS=your_wazuh_password

# Splunk REST API (Free license — port 8089)
SPLUNK_URL=https://localhost:8089
SPLUNK_USER=admin
SPLUNK_PASS=
SPLUNK_INDEX=windows
SPLUNK_POLL_INTERVAL_SECONDS=60
```

```bash
npm run dev
```

### Dashboard

```bash
cd Dashboard
npm install
npm run dev
```

### External Access (Wazuh webhook)

```bash
ngrok http 3000
```

Paste the ngrok URL into the Wazuh Manager `ossec.conf` integration block.

---

## Webhook Endpoints

| Source | Endpoint | Purpose |
|--------|----------|---------|
| Wazuh Manager | `POST /api/webhook/wazuh` | Receive Wazuh rule alerts |

Splunk alerts are handled via polling — no inbound webhook required.

---

## Active Response

For rules with `severity >= 12`, the backend automatically calls the Wazuh API to run `firewall-drop` on the affected agent. This requires the following block in the Wazuh Manager `ossec.conf`:

```xml
<command>
  <name>firewall-drop</name>
  <executable>firewall-drop</executable>
  <timeout_allowed>yes</timeout_allowed>
</command>

<active-response>
  <command>firewall-drop</command>
  <location>local</location>
  <timeout>180</timeout>
</active-response>
```

---

## Rule Documentation

See the `docs/` folder for per-technique documentation including detection logic, test procedures, and Splunk verification screenshots.
