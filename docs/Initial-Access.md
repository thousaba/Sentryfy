### INITIAL ACCESS (T0001)

---
### PHISHING (T1566) - SUSPICIOUS FILE CREATION FROM COMMUNICATION APPS
This rule detects the initial stage of a phishing attack by monitoring for suspicious file types (LNK, EXE, BAT, JS, etc.) being written to the disk by common communication or browser applications. This is a primary indicator of Initial Access, occurring when a user downloads a malicious attachment or is redirected to a drive-by download.

It monitors Sysmon EventID 11 (File Create). By filtering out legitimate system processes like explorer.exe or msiexec.exe, the rule highlights instances where applications like outlook.exe, chrome.exe, or teams.exe drop executable or script files into user-writable directories.

This matters because catching the file at the moment of creation—before it is ever executed—allows for proactive containment. If an analyst can identify a malicious .lnk or .vbs file being dropped by an email client, they can intervene before the user even has a chance to double-click and trigger the execution phase.

# A. Writing the Splunk Query

- [Phishing](../Rules/Splunk-SPL/Initial-Access/phishing.spl) 👈

# B. Testing the Rule 

To simulate this initial access vector, we run a PowerShell script that creates a malicious shortcut (.LNK) file on the desktop, mimicking a common phishing technique.

```powershell
$shell = New-Object -ComObject WScript.Shell
$shortcut = $shell.CreateShortcut("$env:USERPROFILE\Desktop\2026_Maas_Zam_Listesi.lnk")
$shortcut.TargetPath = "powershell.exe"
$shortcut.Arguments = "-ExecutionPolicy Bypass -WindowStyle Hidden -Command Write-Host 'Phishing'"
$shortcut.Save()
```

# C. Log Verification in Splunk

The Splunk dashboard captures the Event ID 11 immediately. In the results, we can see the exact process that created the file (e.g., powershell.exe in our test, or outlook.exe in a real attack) and the full path to the dropped artifact. This provides immediate forensic evidence of how the threat entered the environment.

![Splunk Search](../screenshots/phishing-1.png?v=2)

---
### EXPLOIT PUBLIC-FACING APPLICATION (T1190)
This rule detects attempts to exploit vulnerabilities in internet-facing applications. Specifically, it targets OS Command Injection flaws where an attacker manipulates application inputs (such as HTTP parameters) to execute arbitrary system commands on the underlying host.

It monitors Sysmon EventID 1 (Process Creation). The detection logic focuses on suspicious child processes (like whoami.exe, net.exe, or powershell.exe) being spawned by command interpreters (cmd.exe) that were executed via cmd.exe /c.

This matters because exploiting a public-facing application is a direct path to Initial Access. Once an attacker achieves Remote Code Execution (RCE), they immediately run discovery commands (like whoami) to understand their privileges, user context, and the environment before moving laterally or establishing persistence.

# A. Writing the Splunk Query

- [Phishing](../Rules/Splunk-SPL/Initial-Access/phishing.spl) 👈

# B. Testing the Rule

To simulate this attack, we deploy a deliberately vulnerable Python Flask web application. The application takes an ip parameter via a GET request and passes it directly to the system's ping command without any sanitization or validation.

- [Phishing](../payload/exploit-public-app.py) 

We exploit this by injecting a command separator (&) into the URL parameter via the browser. By accessing http://localhost:5000/ping?ip=8.8.8.8 & whoami, the application executes both the legitimate ping command and our injected whoami payload, returning the host's system information directly to the web screen.

![Test Result](../screenshots/exploit-public-app-1.png?v=2)

# C. Log Verification in Splunk 

Using our Splunk query, we can track the exact execution flow triggered by the web server. The logs show that cmd.exe spawned whoami.exe. Most importantly, the Enjeksiyon_Payloadu field captures the exact raw command line executed (cmd.exe /c ping -n 1 8.8.8.8 & whoami), providing undeniable forensic evidence of the Remote Code Execution (RCE).

![Splunk Search](../screenshots/exploit-public-app-2.png?v=2)


---
### REPLICATION THROUGH REMOVABLE MEDIA (T1091) : UNAUTHORIZED USB DEVICE CONNECTED

We write a rule to generate alerts when unknown USB devices are connected to the system.

# A. Writing the Rule with Sigma

Click the link to access the rule file.
- [Sigma Rule (YML Format)](../Rules/Sigma/unauthorize_usb.yml) 👈 


# B. Testing the Rule

We connect a USB device that is not on the whitelist in the rule to our computer.

# C. Log Verification in Splunk

As seen, Windows printer drivers and audio devices also belong to the "Plug and Play" mechanism, so their logs started appearing as false positives. However, our goal is only to detect physically connected external USB devices.

![splunk search results](../screenshots/splunk-usb-1.png?v=2)

For this reason, we add the following filter to our rule:

```
filter_noise:
    win.eventdata.className:
      - 'PrintQueue'          # Virtual printer queues
      - 'SoftwareDevice'      # Software virtual devices
      - 'AudioEndpoint'       # Audio device plug/unplug noise
    win.eventdata.deviceDescription|contains:
      - 'Microsoft Print to PDF'
      - 'Root Print Queue'
      - 'Generic software device'
```

As shown below, we have successfully suppressed the false positive logs.

- [Sigma Rule (YML Format)](../Rules/Sigma/brute-force.yml) 👈 


---
### SUB-TECHNIQUE: HARDWARE ADDITIONS (T1200) USB-Originating Threat Detection (Risk-Based Scoring)

Since correlation rules are not compatible with Sigma format, we will implement this type of rule directly as a Splunk query.

This rule is designed to detect suspicious processes triggered shortly after a USB device is connected to the system, and to analyze the threat level of these processes using Risk-Based Alerting (RBA).

---
# A. Writing the Splunk Query

- [Splunk SPL](../Rules/Splunk-SPL/Initial-Access/usb-threat-detection.spl) 👈 


Rather than a static detection, the rule establishes a dynamic correlation between two distinct events:

    1- USB Connection Detection (Event Code 6416): Triggered when a new device is connected. Known and trusted devices (Whitelist) are filtered by DeviceId.
    2- Process Creation (Event Code 4688): All processes started within 30 seconds of the USB connection are monitored.

---
The query evaluates each suspicious activity it captures with a "Risk Score." The higher the score, the greater the alert severity:

    Process Identity (+5 Points): A base score is assigned if attacker-favored tools (LOLBins) such as powershell.exe, cmd.exe, rundll32.exe, or mshta.exe are detected.

    Command Line Analysis (+1 to +3 Points):
        Encoded command usage (-enc, EncodedCommand).
        Attempts to download files from the internet (DownloadString, WebClient).
        Hidden window or privilege bypass (-WindowStyle Hidden, -ExecutionPolicy Bypass).

    Parent-Child Process Analysis (+2 to +4 Points): If the process is spawned by system services such as services.exe or lsass.exe instead of explorer.exe (normal user), it is scored as "critical" risk.

    Time Bonus (+2 to +3 Points): Processes starting within the first 5 seconds after a USB connection are given extra points as a direct indicator of a hardware attack (BadUSB/Rubber Ducky).

---
# B. False Positive Management

To avoid overwhelming SOC operations, the following scenarios are automatically excluded or have their score reduced:

    PnP Driver Installations: Legitimate driver processes started by Windows for the connected device (streamci, shell32.dll calls, etc.) are filtered out.
    Legitimate Software: Routine checks triggered by Splunk's own Python services are suppressed to reduce noise.

---
# C. Log Verification in Splunk

![Splunk Search](../screenshots/splunk-usb-4.png?v=2)

---

### HARDWARE ADDITIONS (T1200) USB HID (KEYBOARD) DETECTION — BADUSB 

"This rule is designed to detect Rubber Ducky/BadUSB attacks (MITRE T1200) that exploit the operating system's blind trust in peripherals by emulating HID (Human Interface Device) behavior."

A normal user does not plug in a new keyboard every day at work. If a new device suddenly appears in the HIDClass or Keyboard class on a machine, there are two possibilities:

  1- The user's keyboard broke and they plugged in a new one. (False Positive)
  2- Someone plugged that sneaky Rubber Ducky into the machine and is currently injecting commands into your PowerShell at 1000 words per second. (Critical Attack)

# A. Writing the Splunk Query

One important thing to keep in mind when writing this rule is to whitelist our own mouse and keyboard devices. Otherwise, we will be flooded with false positive alerts.

- [Splunk SPL](../Rules/Splunk-SPL/Initial-Access/usb-hid-detection.spl) 👈


# B. Log Verification in Splunk

![Splunk Search](../screenshots/splunk-usb-5.png?v=2)

---

### VALID ACCOUNTS (T1078)
This rule detects the use of Valid Accounts, a defense evasion and initial access technique where attackers utilize compromised credentials (local, domain, or cloud) to bypass access controls. Since the adversary logs in acting exactly like a legitimate user, this activity blends seamlessly into normal daily network traffic.

It monitors Security EventID 4648 (A logon was attempted using explicit credentials) and correlates it with suspicious processes like runas.exe. While administrators occasionally use runas for legitimate troubleshooting, an unexpected spike or usage from a standard user context often indicates an attacker pivoting or elevating privileges using a stolen valid account.

This matters because once attackers possess valid credentials, they no longer need to rely on noisy malware or exploits. They simply log in, access data, and move laterally. Detecting this requires hunting for anomalous credential usage—specifically, a user process explicitly supplying credentials to authenticate as a different, higher-privileged account

# A. Writing the Splunk Query
- [Splunk SPL](../Rules/Splunk-SPL/Initial-Access/valid-accounts.spl) 👈

# B. Testing the Rule
To simulate an attacker leveraging a valid account to escalate privileges locally, we use the built-in Windows runas utility. Assuming the attacker has already dumped or cracked the password for the local or domain Administrator, they use this command to spawn a new command shell running under that high-privileged context.

![Splunk Search](../screenshots/valid-accounts-1.png?v=2)

# C. Log Verification in Splunk 
By searching for Event ID 4648 in our Splunk dashboard, we can clearly see the exact moment the explicit credentials were used. The log explicitly shows the Tetikleyen_Kullanici (the initial compromised low-privilege shell) and the Ele_Gecirilen_Hesap (the Administrator account the attacker pivoted into). This provides the SOC analyst with immediate visibility into which valid accounts are actively being abused on the endpoint.

![Splunk Search](../screenshots/valid-accounts-2.png?v=2)