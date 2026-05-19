# MITRE ATT&CK Coverage Analysis

Bu doküman, Sentryfy projesinin **şu an kapsadığı** detection kurallarını ve **hedeflenen** teknikleri MITRE ATT&CK framework'üne göre haritalar. Detection engineering çalışmasının ilerleyişini ve portföy kapsamını şeffaf şekilde göstermek için tutulur.

---

## 📊 Genel Durum

| Metrik | Değer |
|--------|-------|
| Toplam kapsanan teknik | **18** |
| Kapsanan tactic sayısı | **6 / 14** |
| Yüksek öncelik gap (önerilen sonraki kurallar) | **20+** |
| Hiç kapsanmayan tactic | **8** |

**Lejant:**
- ✅ Kapsanan — kural yazılmış, lab'de test edilmiş
- 🔥 Yüksek öncelik — bir sonraki sprint'lerde yazılacak
- ⏳ Orta öncelik — roadmap'te, sonra gelecek
- ❌ Boş tactic — şu an hiç kural yok

---

## TA0001 — Initial Access

**Kapsam: 4/9 teknik — iyi durum** 🟢

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

**Kapsam: 1/13 teknik — kritik eksiklik** 🔴

LOLBin tabanlı execution detection neredeyse hiç yok. PowerShell dışında klasik komut satırı çalıştırma yöntemleri tamamen boşta.

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

**Kapsam: 2/19 teknik — kritik eksiklik** 🔴

Persistence'ın en yaygın yöntemleri (Run keys, Windows Service, WMI subscription) henüz kapsanmıyor.

| Durum | Teknik ID | Teknik Adı | Kural Dosyası |
|-------|-----------|-----------|---------------|
| ✅ | T1098 | Account Manipulation | `Persistence/account-manipulation.spl` |
| ✅ | T1053.005 | Scheduled Task | `Persistence/scheduled-task.spl` |
| 🔥 | T1547.001 | Registry Run Keys / Startup Folder | _planned_ |
| 🔥 | T1543.003 | Windows Service | _planned_ |
| 🔥 | T1136 | Local Account Creation | _planned_ |
| 🔥 | T1546.003 | WMI Event Subscription | _planned_ |
| 🔥 | T1546.008 | Accessibility Features (sethc / utilman) | _planned_ |
| 🔥 | T1505.003 | Web Shell | _planned_ |

---

## TA0004 — Privilege Escalation

**Kapsam: 5/14 teknik — güçlü alan** 🟢

Process injection ailesi için advanced seviye kurallar mevcut. Portföyün en öne çıkan kısmı.

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

**Kapsam: 5/43 teknik — sayıca düşük ama güçlü teknikler** 🟡

Kapsanan teknikler advanced seviye (PPL bypass, PPID spoofing) ama yaygın evasion yöntemleri (obfuscation, registry modification) eksik.

| Durum | Teknik ID | Teknik Adı | Kural Dosyası |
|-------|-----------|-----------|---------------|
| ✅ | T1562.001 | Disable or Modify Tools (Windows Defender) | `Defense-Evasion/win-defender.spl` |
| ✅ | T1070.001 | Clear Windows Event Logs | `Defense-Evasion/event-log-clearing.spl` |
| ✅ | T1036.003 | Process Masquerading (svchost.exe) | `Defense-Evasion/svchost.spl` |
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

**Kapsam: 1/17 teknik — kritik eksiklik** 🔴

LSASS dump (Mimikatz'in en temel hareketi) henüz yok. PPL bypass kuralıyla pair yapacak en önemli detection eksik.

| Durum | Teknik ID | Teknik Adı | Kural Dosyası |
|-------|-----------|-----------|---------------|
| ✅ | T1110 | Brute Force | `Credential-Access/brute-force.spl` + Sigma |
| 🔥 | T1003.001 | OS Credential Dumping: LSASS Memory | _planned_ |
| 🔥 | T1555 | Credentials from Password Stores (browsers) | _planned_ |
| 🔥 | T1558.003 | Kerberoasting | _planned_ |
| 🔥 | T1552.001 | Unsecured Credentials in Files | _planned_ |

---

## ❌ Hiç Kapsanmayan Tactic'ler

Aşağıdaki 8 tactic için **tek bir kural bile yok**. Kill chain'in ikinci yarısı tamamen boş — Sentryfy şu an "saldırgan içeri girdi, sonra ne oldu?" sorusuna cevap veremiyor.

### TA0007 — Discovery
- T1087 Account Discovery
- T1018 Remote System Discovery
- T1082 System Information Discovery
- T1016 System Network Configuration Discovery

### TA0008 — Lateral Movement
- T1021.001 Remote Desktop Protocol (RDP)
- T1021.002 SMB / Windows Admin Shares
- T1570 Lateral Tool Transfer

### TA0009 — Collection
- T1560 Archive Collected Data
- T1005 Data from Local System

### TA0011 — Command and Control
- T1071.001 Application Layer Protocol: HTTP/S
- T1572 Protocol Tunneling

### TA0010 — Exfiltration
- T1041 Exfiltration Over C2 Channel
- T1567 Exfiltration Over Web Service

### TA0040 — Impact
- T1486 Data Encrypted for Impact (Ransomware)
- T1490 Inhibit System Recovery (vssadmin / shadow copy deletion)

### TA0042 — Resource Development
*Portföy için düşük öncelik — saldırgan tarafı, mavi takım odağında değil.*

### TA0043 — Reconnaissance
*Portföy için düşük öncelik — saldırı öncesi pasif aşama, network'ten görünmüyor.*

---

## 🎯 Önerilen Yazma Sırası

Coverage gap'ini en hızlı kapatmak için önerilen sıra:

| # | Teknik | Tactic | Neden öncelik? |
|---|--------|--------|----------------|
| 1 | **T1003.001 LSASS Access** | Credential Access | Mimikatz'in temel hareketi, PPL bypass kuralıyla pair yapar |
| 2 | **T1547.001 Run Keys** | Persistence | Persistence'ta en yaygın yöntem, Sysmon Event ID 13 ile kolay |
| 3 | **T1218.011 Rundll32 abuse** | Execution / Defense Evasion | Klasik LOLBin, gerçek APT'lerde her yerde var |
| 4 | **T1071.001 C2 HTTP** | Command and Control | Yeni tactic açar, beaconing detection portföyde özgün durur |
| 5 | **T1021.001/002 RDP / SMB** | Lateral Movement | Kill chain'in ikinci yarısını açar |
| 6 | **T1486 Ransomware behavior** | Impact | Yüksek görünürlüklü, kısa sürede çok dosya yazma + `vssadmin delete shadows` |

İlk 3'ü bitirdiğinde coverage **18 → 21** olur ve her major tactic'te en az 2 kural olur. 4-6 arası ise kill chain'in ikinci yarısını açan ilk adımlar.

---

## 📁 Repo Yapısı

```
Sentryfy/
├── Initial-Access/
│   ├── phishing.spl
│   ├── exploit-public-app.spl
│   ├── unauthorized-usb.spl
│   ├── usb-threat-detection.spl
│   └── usb-hid-detection.spl
├── Execution/
│   └── suspicious-command.spl
├── Persistence/
│   ├── account-manipulation.spl
│   └── scheduled-task.spl
├── Privilege-Escalation/
│   ├── dll-injection.spl
│   ├── process-hollowing.spl
│   ├── early-bird.spl
│   ├── byovd.spl
│   └── uac-bypass.spl
├── Defense-Evasion/
│   ├── win-defender.spl
│   ├── event-log-clearing.spl
│   ├── svchost.spl
│   ├── ppl-disabled.spl
│   └── ppid-spoof.spl
├── Credential-Access/
│   └── brute-force.spl
└── Sigma/
    ├── unauthorized_usb.yml
    ├── suspicious-command.yml
    └── brute-force.yml
```

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

*Son güncelleme: 19 Mayıs 2026 ·*