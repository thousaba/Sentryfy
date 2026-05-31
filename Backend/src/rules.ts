// SPL sorguları Rules/Splunk-SPL/ altındaki .spl dosyalarında yaşar.
// Bu dosya sadece metadata + dosya yolu tutar.

export interface SplunkRule {
  id:          string;
  name:        string;
  mitre:       string;
  severity:    number;    // 1–12
  ar_command?: string;    // ossec.conf'ta tanımlı AR komutu
  splFile:     string;    // repo kökünden göreli yol
}

export const RULES: SplunkRule[] = [
  {
    id:       'brute-force',
    name:     'Brute Force — Multiple Failed Logins (T1110)',
    mitre:    'T1110',
    severity: 10,
    splFile:  'Rules/Splunk-SPL/Credential-Access/brute-force.spl',
  },
  {
    id:       'phishing-file-drop',
    name:     'Phishing — Suspicious File Dropped by Mail/Browser App (T1566)',
    mitre:    'T1566',
    severity: 10,
    splFile:  'Rules/Splunk-SPL/Initial-Access/phishing.spl',
  },
  {
    id:       'exploit-public-app',
    name:     'Exploit Public-Facing Application (T1190)',
    mitre:    'T1190',
    severity: 12,
    splFile:  'Rules/Splunk-SPL/Initial-Access/exploit-public-app.spl',
  },
  {
    id:       'valid-accounts',
    name:     'Valid Accounts — Explicit Credential Usage (T1078)',
    mitre:    'T1078',
    severity: 8,
    splFile:  'Rules/Splunk-SPL/Initial-Access/valid-accounts.spl',
  },
  {
    id:       'usb-threat',
    name:     'USB-Originating Threat Detection — Hardware Additions (T1200)',
    mitre:    'T1200',
    severity: 10,
    splFile:  'Rules/Splunk-SPL/Initial-Access/usb-threat-detection.spl',
  },
  {
    id:       'usb-hid',
    name:     'BadUSB / HID Keyboard Detection (T1200)',
    mitre:    'T1200',
    severity: 10,
    splFile:  'Rules/Splunk-SPL/Initial-Access/usb-hid-detection.spl',
  },
  {
    id:       'suspicious-command',
    name:     'Suspicious PowerShell Command (T1059.001)',
    mitre:    'T1059.001',
    severity: 8,
    splFile:  'Rules/Splunk-SPL/Execution/suspicious-command.spl',
  },
  {
    id:       'account-manipulation',
    name:     'Account Manipulation — Admin Rename/Add (T1098)',
    mitre:    'T1098',
    severity: 8,
    splFile:  'Rules/Splunk-SPL/Persistence/account-manipulation.spl',
  },
  {
    id:       'scheduled-task',
    name:     'Suspicious Scheduled Task Created (T1053.005)',
    mitre:    'T1053.005',
    severity: 10,
    splFile:  'Rules/Splunk-SPL/Persistence/scheduled-task.spl',
  },
  {
    id:       'defender-disabled',
    name:     'Windows Defender Disabled — Impair Defenses (T1562.001)',
    mitre:    'T1562.001',
    severity: 12,
    splFile:  'Rules/Splunk-SPL/Defense-Evasion/win-defender.spl',
  },
  {
    id:       'event-log-clear',
    name:     'Event Log Cleared — Indicator Removal (T1070.001)',
    mitre:    'T1070.001',
    severity: 12,
    splFile:  'Rules/Splunk-SPL/Defense-Evasion/event-log-clearing.spl',
  },
  {
    id:       'svchost-masquerade',
    name:     'svchost Masquerading — Process Masquerading (T1036.003)',
    mitre:    'T1036.003',
    severity: 10,
    splFile:  'Rules/Splunk-SPL/Defense-Evasion/svchost.spl',
  },
  {
    id:       'ppl-disabled',
    name:     'LSA Protection Disabled — PPL Tamper (T1562.001)',
    mitre:    'T1562.001',
    severity: 12,
    splFile:  'Rules/Splunk-SPL/Defense-Evasion/ppl-disabled.spl',
  },
  {
    id:       'ppid-spoof',
    name:     'Parent PID Spoofing — Access Token Manipulation (T1134.004)',
    mitre:    'T1134.004',
    severity: 10,
    splFile:  'Rules/Splunk-SPL/Defense-Evasion/ppid-spoof.spl',
  },
  {
    id:       'dll-injection',
    name:     'DLL Injection — Remote Thread Injection (T1055.002)',
    mitre:    'T1055.002',
    severity: 12,
    ar_command: 'firewall-drop',
    splFile:  'Rules/Splunk-SPL/Privilege-Escalation/dll-injection.spl',
  },
  {
    id:       'process-hollowing',
    name:     'Process Hollowing — Transacted Hollowing (T1055.012)',
    mitre:    'T1055.012',
    severity: 12,
    splFile:  'Rules/Splunk-SPL/Privilege-Escalation/process-hollowing.spl',
  },
  {
    id:       'early-bird-apc',
    name:     'Early Bird APC Injection (T1055.004)',
    mitre:    'T1055.004',
    severity: 12,
    splFile:  'Rules/Splunk-SPL/Privilege-Escalation/early-bird.spl',
  },
  {
    id:       'uac-bypass',
    name:     'UAC Bypass via fodhelper (T1548.002)',
    mitre:    'T1548.002',
    severity: 12,
    splFile:  'Rules/Splunk-SPL/Privilege-Escalation/uac-bypass.spl',
  },
  {
    id:       'byovd',
    name:     'BYOVD — Vulnerable Driver Install (T1068)',
    mitre:    'T1068',
    severity: 12,
    splFile:  'Rules/Splunk-SPL/Privilege-Escalation/byovd.spl',
  },
];
