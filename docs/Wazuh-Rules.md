# Sentryfy — Wazuh-Based Real-Time SIEM Dashboard

A security monitoring project that collects logs via Wazuh on a Windows agent, generates alerts with custom rules, sends Telegram notifications, and features a live React dashboard.

---

## Architecture

```
Windows Agent (Wazuh) → Wazuh Manager → Webhook (ngrok) → Node.js Backend → React Dashboard
                                                                          ↓
                                                                   Telegram Bot
```

---

## Setup & Configuration

### 1. Wazuh Agent — ossec.conf Log Sources

Log sources to be monitored were added to the Windows agent.

![ossec.conf localfile config](../screenshots/ss1.png?v=2)

### 2. Enabling Windows Audit Policy

Audit policy was enabled via `auditpol` to log failed login events.

![auditpol powershell](../screenshots/ss2.png?v=2)

### 3. Custom Wazuh Rules

Custom rules were defined for Windows failed login and USB connection events.

![custom wazuh rules](../screenshots/ss5.png?v=2)

### 4. Wazuh Webhook Integration

Wazuh manager was configured to forward alerts to the backend via ngrok.

![wazuh integration config](../screenshots/ss6.png?v=2)

### 5. ngrok Tunnel

ngrok was used to expose the backend to external access.

![ngrok tunnel](../screenshots/ss4.png?v=2)

### 6. Backend Code

Alerts received from the webhook were processed using Express + Socket.IO + Telegram integration.

![backend code](../screenshots/ss3.png?v=2)

---

## Testing

### Failed Login Attempt with Wrong Credentials

An intentional failed login attempt was made using the `runas` command.

![failed login test](../screenshots/ss7.png?v=2)

---

## Results

### Wazuh Discover — Alerts

![wazuh discover login](../screenshots/ss9.png?v=2)

![wazuh discover usb](../screenshots/ss10.png?v=2)

### React Dashboard

![sentryfy dashboard](../screenshots/ss8.png?v=2)

### Telegram Notifications

![telegram alerts](../screenshots/signal-ss.jpeg?v=2)

### Our personal USB device is recognized by the system while other devices trigger an alert:

![sentryfy dashboard](../screenshots/ss11.png?v=2)


### The result is visible on Wazuh's log screen (the name of the connected USB device is also displayed dynamically):
![sentryfy dashboard](../screenshots/ss12.png?v=2)
