# MITRE ATT&CK Coverage Analysis

This document maps the detection rules **currently covered** by the Sentryfy project and the **targeted** techniques against the MITRE ATT&CK framework. It is maintained to transparently show the progress of detection engineering work and the scope of the portfolio.

---

**Legend:**
- ✅ Covered — rule written and tested in lab
- ⏳ Medium priority — on the roadmap, coming later

---

## TA0001 — Initial Access


| Status | Technique ID | Technique Name | SPL File |
|--------|--------------|----------------|-----------|
| ✅ | T1566 | Phishing (Suspicious File Creation) | [Phishing SPL](./Rules/Splunk-SPL/Initial-Access/phishing.spl) |
| ✅ | T1190 | Exploit Public-Facing Application | [Exploit Public App SPL](./Rules/Splunk-SPL/Initial-Access/exploit-public-app.spl) |
| ✅ | T1200 | Hardware Additions (BadUSB / HID) | [Hardware Additions SPL](./Rules/Splunk-SPL/Initial-Access/hardware-additions.spl) |
| ✅ | T1078 | Valid Accounts (login anomaly) | [Valid Accounts](./Rules/Splunk-SPL/Initial-Access/valid-accounts.spl) |
| ⏳ | T1133 | External Remote Services (RDP) | _planned_ |
| ⏳ | T1195 | Supply Chain Compromise | _planned_ |
| ⏳ | T1199 | Trusted Relationship | _planned_ |

---

## TA0002 — Execution


| Status | Technique ID | Technique Name | SPL File |
|--------|--------------|----------------|-----------|
| ✅ | T1059.003 | Windows Command Shell (cmd.exe) | [Windows Command Shell SPL](./Rules/Splunk-SPL/Execution/proccreate.spl) |
| ⏳ | T1059.005 | Visual Basic (wscript / cscript) | _planned_ |
| ⏳ | T1059.007 | JavaScript | _planned_ |
| ⏳ | T1047 | Windows Management Instrumentation (WMI) | _planned_ |
| ⏳ | T1218.010 | Regsvr32 (Squiblydoo) | _planned_ |
| ⏳ | T1218.011 | Rundll32 abuse | _planned_ |
| ⏳ | T1203 | Exploitation for Client Execution | _planned_ |

---

## TA0003 — Persistence


| Status | Technique ID | Technique Name | SPL File |
|--------|--------------|----------------|-----------|
| ✅ | T1098 | Account Manipulation | [Account Manipulation](./Rules/Splunk-SPL/Persistence/account-manipulation.spl) |
| ✅ | T1053.005 | Scheduled Task | [Scheduled Task SPL](./Rules/Splunk-SPL/Persistence/scheduled-task-v2) |
| ✅ | T1176 | Browser Extensions | [Browser Extensions](./Rules/Splunk-SPL/Persistence/browser-extensions.spl) |
| ✅ | T1547.001 | Registry Run Keys / Startup Folder | [Registry Run Keys SPL](./Rules/Splunk-SPL/Persistence/registry_run_keys.spl) |
| ⏳ | T1543.003 | Windows Service | _planned_ |
| ⏳ | T1136 | Local Account Creation | _planned_ |
| ⏳ | T1546.003 | WMI Event Subscription | _planned_ |
| ⏳ | T1546.008 | Accessibility Features (sethc / utilman) | _planned_ |
| ⏳ | T1505.003 | Web Shell | _planned_ |

---

## TA0004 — Privilege Escalation


| Status | Technique ID | Technique Name | SPL File |
|--------|--------------|----------------|-----------|
| ✅ | T1055.002 | Process Injection: Remote Thread (DLL Injection) | [DLL Injection](./Rules/Splunk-SPL/Privilege-Escalation/dll-injection.spl) |
| ✅ | T1055.012 | Process Injection: Process Hollowing | [Process Hollowing SPL](./Rules/Splunk-SPL/Privilege-Escalation/process-hollowing.spl) |
| ✅ | T1055.004 | Process Injection: APC (Early Bird) | [Early Bird SPL](./Rules/Splunk-SPL/Privilege-Escalation/early-bird.spl) |
| ✅ | T1068 | Exploitation for Privilege Escalation (BYOVD) | [BYOVD SPL](./Rules/Splunk-SPL/Privilege-Escalation/byovd.spl) |
| ✅ | T1548.002 | Bypass User Account Control (fodhelper) | [Bypass UAC SPL](./Rules/Splunk-SPL/Privilege-Escalation/uac-bypass.spl) |
| ⏳ | T1134.001 | Access Token Manipulation: Token Impersonation | _planned_ |
| ⏳ | T1055.003 | Thread Execution Hijacking | _planned_ |
| ⏳ | T1574.002 | DLL Side-Loading | _planned_ |

---

## TA0005 — Defense Evasion


| Status | Technique ID | Technique Name | SPL File |
|--------|--------------|----------------|-----------|
| ✅ | T1562.001 | Disable or Modify Tools (Windows Defender) | [Win-Defender SPL](./Rules/Splunk-SPL/Defense-Evasion/win-defender.spl) |
| ✅ | T1036.003 | Process Masquerading (svchost.exe) | [Process Masquerading SPL](./Rules/Splunk-SPL/Defense-Evasion/svchost.spl) |
| ✅ | T1036.008 | Masquerading: Masquerade File Type | [Masquerading SPL](./Rules/Splunk-SPL/Defense-Evasion/masquerade-file-type.spl) |
| ✅ | T1562.001 | Disable or Modify Tools (PPL / LSA Protection) | [PPL Disabled SPL](./Rules/Splunk-SPL/Defense-Evasion/ppl-disabled.spl) |
| ✅ | T1134.004 | Parent PID Spoofing | [PPID Spoofing SPL](./Rules/Splunk-SPL/Defense-Evasion/ppid-spoof.spl) |
| ✅ | T1218.005 | Mshta abuse | [Mshta Abuse SPL](./Rules/Splunk-SPL/Defense-Evasion/system_binary_proxy_execution.spl) |
| ⏳ | T1070.001 | Clear Windows Event Logs | _planned_ |
| ⏳ | T1027 | Obfuscated Files (base64, encoded commands) | _planned_ |
| ⏳ | T1140 | Deobfuscate / Decode Files or Information | _planned_ |
| ⏳ | T1112 | Modify Registry | _planned_ |
| ⏳ | T1070.004 | File Deletion | _planned_ |
| ⏳ | T1497 | Virtualization / Sandbox Evasion | _planned_ |
| ⏳ | T1564.001 | Hidden Files and Directories | _planned_ |

---

## TA0006 — Credential Access


| Status | Technique ID | Technique Name | SPL File | KQL File |
|--------|--------------|----------------|-----------|----------|
| ✅ | T1110 | Brute Force | [Brute Force SPL](./Rules/Splunk-SPL/Credential-Access/brute-force.spl) | [Brute Force KQL](./Rules/Sentinel-KQL/Credential-Access/bruteforce.kql) |
| ✅ | T1110.003 | Password Spraying | [Password Spraying SPL](./Rules/Splunk-SPL/Credential-Access/password-spraying.spl) | [Password Spraying KQL](./Rules/Sentinel-KQL/Credential-Access/password-spraying.kql) |
| ✅ | T1003.001 | OS Credential Dumping: LSASS Memory | [LSASS Memory SPL](./Rules/Splunk-SPL/Credential-Access/lsass-access.spl) |
| ⏳ | T1555 | Credentials from Password Stores (browsers) | _planned_ | |
| ⏳ | T1558.003 | Kerberoasting | _planned_ | |
| ⏳ | T1552.001 | Unsecured Credentials in Files | _planned_ | |

---

## TA0007 — Discovery


| Status | Technique ID | Technique Name | SPL File |
|--------|--------------|----------------|-----------|
| ⏳ | T1087.001 | Account Discovery: Local Account | _planned_ |
| ⏳ | T1018 | Remote System Discovery | _planned_ |
| ⏳ | T1082 | System Information Discovery | _planned_ |
| ⏳ | T1016 | System Network Configuration Discovery | _planned_ |

---

### TA0008 — Lateral Movement

| Status | Technique ID | Technique Name | SPL File |
|--------|--------------|----------------|-----------|
| ✅ | T1021.002 | Remote Services: SMB/Windows Admin Share | [Admin Share SPL](./Rules/Splunk-SPL/Lateral-Movement/admin-shares.spl) |
| ✅ | T1570 | Lateral Tool Transfer | [Lateral Tool Transfer SPL](./Rules/Splunk-SPL/Lateral-Movement/lateral-tool-transfer.spl) |


---

### TA0011 — Command and Control

| Status | Technique ID | Technique Name | SPL File |
|--------|--------------|----------------|-----------|
| ✅ | T1219 | Remote Access Tools | [Remote Access Tools SPL](./Rules/Splunk-SPL/Command-and-Control/remote-access-tools.spl) |
| ✅ | T1071.004 | Application Layer Protocol: DNS Tunneling | [DNS Tunneling SPL](./Rules/Splunk-SPL/Command-and-Control/dns-tunneling.spl) |
| ✅ | T1071.004 + T1048.003 | DNS Tunneling (Network-Based + Process Correlation) | [DNS Tunneling Correlation SPL](./Rules/Splunk-SPL/Command-and-Control/dns-tunneling-correlation.spl) |
| ⏳ | T1572 | Protocol Tunneling | _planned_ |


---

## 🔬 Test Environment

All rules are written and tested in the following environment:

- **OS:** Windows 11
- **EDR/Telemetry:** Sysmon (config: SwiftOnSecurity baseline + custom additions) + Windows Event Logs 
- **SIEM:** Splunk Developer License (Free license, lab use)  + Microsoft Sentinel (free trial, lab use)
---
