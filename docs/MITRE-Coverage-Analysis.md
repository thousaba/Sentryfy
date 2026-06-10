# MITRE ATT&CK Coverage Analysis

Bu doküman, Sentryfy projesinin **şu an kapsadığı** detection kurallarını ve **hedeflenen** teknikleri MITRE ATT&CK framework'üne göre haritalar. Detection engineering çalışmasının ilerleyişini ve portföy kapsamını şeffaf şekilde göstermek için tutulur.

---

**Lejant:**
- ✅ Kapsanan — kural yazılmış, lab'de test edilmiş
- 🔥 Yüksek öncelik — bir sonraki sprint'lerde yazılacak
- ⏳ Orta öncelik — roadmap'te, sonra gelecek
- ❌ Boş tactic — şu an hiç kural yok

---

## TA0001 — Initial Access


| Durum | Teknik ID | Teknik Adı | Kural Dosyası |
|-------|-----------|-----------|---------------|
| ✅ | T1566 | Phishing (Suspicious File Creation) | `Initial-Access/phishing.spl` |
| ✅ | T1190 | Exploit Public-Facing Application | `Initial-Access/exploit-public-app.spl` |
| ✅ | T1091 | Replication Through Removable Media | `Initial-Access/unauthorized-usb.spl` + Sigma |
| ✅ | T1200 | Hardware Additions (BadUSB / HID) | `Initial-Access/usb-threat-detection.spl` + `usb-hid-detection.spl` |
| ✅ | T1078 | Valid Accounts (login anomaly) | `Initial-Access/valid-accounts.spl` |
| ⏳ | T1133 | External Remote Services (RDP) | _planned_ |
| ⏳ | T1195 | Supply Chain Compromise | _planned_ |
| ⏳ | T1199 | Trusted Relationship | _planned_ |

---

## TA0002 — Execution


| Durum | Teknik ID | Teknik Adı | Kural Dosyası |
|-------|-----------|-----------|---------------|
| ✅ | T1059.001 | PowerShell (Suspicious Commands) | `Execution/suspicious-command.spl` + Sigma |
| 🔥 | T1059.003 | Windows Command Shell (cmd.exe) | _planned_ |
| 🔥 | T1059.005 | Visual Basic (wscript / cscript) | _planned_ |
| 🔥 | T1059.007 | JavaScript | _planned_ |
| 🔥 | T1047 | Windows Management Instrumentation (WMI) | _planned_ |
| 🔥 | T1218.005 | Mshta abuse | _planned_ |
| 🔥 | T1218.010 | Regsvr32 (Squiblydoo) | _planned_ |
| 🔥 | T1218.011 | Rundll32 abuse | _planned_ |
| ⏳ | T1203 | Exploitation for Client Execution | _planned_ |

---

## TA0003 — Persistence


| Durum | Teknik ID | Teknik Adı | Kural Dosyası |
|-------|-----------|-----------|---------------|
| ✅ | T1098 | Account Manipulation | `Persistence/account-manipulation.spl` |
| ✅ | T1053.005 | Scheduled Task | `Persistence/scheduled-task.spl` |
| ✅ | T1053.005 | Browser Extensions  | `Persistence/browser-extensions.spl` |
| 🔥 | T1547.001 | Registry Run Keys / Startup Folder | _planned_ |
| 🔥 | T1543.003 | Windows Service | _planned_ |
| 🔥 | T1136 | Local Account Creation | _planned_ |
| 🔥 | T1546.003 | WMI Event Subscription | _planned_ |
| 🔥 | T1546.008 | Accessibility Features (sethc / utilman) | _planned_ |
| 🔥 | T1505.003 | Web Shell | _planned_ |

---

## TA0004 — Privilege Escalation


| Durum | Teknik ID | Teknik Adı | Kural Dosyası |
|-------|-----------|-----------|---------------|
| ✅ | T1055.002 | Process Injection: Remote Thread (DLL Injection) | `Privilege-Escalation/dll-injection.spl` |
| ✅ | T1055.012 | Process Injection: Process Hollowing (Transacted) | `Privilege-Escalation/process-hollowing.spl` |
| ✅ | T1055.004 | Process Injection: APC (Early Bird) | `Privilege-Escalation/early-bird.spl` |
| ✅ | T1068 | Exploitation for Privilege Escalation (BYOVD) | `Privilege-Escalation/byovd.spl` |
| ✅ | T1548.002 | Bypass User Account Control (fodhelper) | `Privilege-Escalation/uac-bypass.spl` |
| ⏳ | T1134.001 | Access Token Manipulation: Token Impersonation | _planned_ |
| ⏳ | T1055.003 | Thread Execution Hijacking | _planned_ |
| ⏳ | T1574.002 | DLL Side-Loading | _planned_ |

---

## TA0005 — Defense Evasion


| Durum | Teknik ID | Teknik Adı | Kural Dosyası |
|-------|-----------|-----------|---------------|
| ✅ | T1562.001 | Disable or Modify Tools (Windows Defender) | `Defense-Evasion/win-defender.spl` |
| ✅ | T1070.001 | Clear Windows Event Logs | `Defense-Evasion/event-log-clearing.spl` |
| ✅ | T1036.003 | Process Masquerading (svchost.exe) | `Defense-Evasion/svchost.spl` |
| ✅ | T1036.008 | Masquerading: Masquerade File Type | `Defense-Evasion/masquerade-file-type.spl` |
| ✅ | T1562.001 | Disable or Modify Tools (PPL / LSA Protection) | `Defense-Evasion/ppl-disabled.spl` |
| ✅ | T1134.004 | Parent PID Spoofing | `Defense-Evasion/ppid-spoof.spl` |
| 🔥 | T1027 | Obfuscated Files (base64, encoded commands) | _planned_ |
| 🔥 | T1140 | Deobfuscate / Decode Files or Information | _planned_ |
| 🔥 | T1112 | Modify Registry | _planned_ |
| 🔥 | T1070.004 | File Deletion | _planned_ |
| ⏳ | T1497 | Virtualization / Sandbox Evasion | _planned_ |
| ⏳ | T1564.001 | Hidden Files and Directories | _planned_ |

---

## TA0006 — Credential Access


| Durum | Teknik ID | Teknik Adı | Kural Dosyası |
|-------|-----------|-----------|---------------|
| ✅ | T1110 | Brute Force | `Credential-Access/brute-force.spl` + Sigma |
| 🔥 | T1003.001 | OS Credential Dumping: LSASS Memory | _planned_ |
| 🔥 | T1555 | Credentials from Password Stores (browsers) | _planned_ |
| 🔥 | T1558.003 | Kerberoasting | _planned_ |
| 🔥 | T1552.001 | Unsecured Credentials in Files | _planned_ |

---

## TA0007 — Discovery


| Durum | Teknik ID | Teknik Adı | Kural Dosyası |
|-------|-----------|-----------|---------------|
| ✅ | T1087.001 | Account Discovery: Local Account | `Discovery/local-account-discovery`|
| 🔥 | T1018 | Remote System Discovery | _planned_ |
| 🔥 | T1082 | System Information Discovery | _planned_ |
| 🔥 | T1016 | System Network Configuration Discovery | _planned_ |

---

### TA0008 — Lateral Movement

| Durum | Teknik ID | Teknik Adı | Kural Dosyası |
|-------|-----------|-----------|---------------|
| ✅ | T1021.002 | SMB / Windows Admin Share | `Lateral-Movement/lateral-tool-transfer` |
| ✅ | T1570 | Lateral Tool Transfer | `Lateral-Movement/smb-admin-shares` |
| 🔥 | T1021.001 | Remote Desktop Protocol (RDP) | _planned_ |


---

### TA0011 — Command and Control

| Durum | Teknik ID | Teknik Adı | Kural Dosyası |
|-------|-----------|-----------|---------------|
| ✅ | T1021.002 | SMB / Windows Admin Share | `Command-and-Control/remote-access-tools`|
| 🔥 | T1071.001 | Application Layer Protocol: HTTP/S | _planned_ |
| 🔥 | T1572 | Protocol Tunneling | _planned_ |

---

## ❌ Hiç Kapsanmayan Tactic'ler

### TA0009 — Collection
- T1560 Archive Collected Data
- T1005 Data from Local System


### TA0010 — Exfiltration
- T1041 Exfiltration Over C2 Channel
- T1567 Exfiltration Over Web Service

### TA0040 — Impact
- T1486 Data Encrypted for Impact (Ransomware)
- T1490 Inhibit System Recovery (vssadmin / shadow copy deletion)


---

## 🔬 Test Ortamı

Tüm kurallar aşağıdaki ortamda yazılır ve test edilir:

- **OS:** Windows 11 
- **EDR/Telemetry:** Sysmon (config: SwiftOnSecurity baseline + custom additions)
- **SIEM:** Splunk Enterprise (Free license, lab kullanım)
- **Sourcetype:** `XmlWinEventLog:Microsoft-Windows-Sysmon/Operational`
- **Alerting:** Telegram webhook üzerinden Node.js backend
- **Aktif güvenlik özellikleri:** LSA Protection (RunAsPPL), HVCI, Secure Boot — gerçekçi attack simulation için

---

*Son güncelleme: 10 Haziran 2026 ·*
