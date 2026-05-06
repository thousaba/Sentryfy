# Sentryfy — Splunk-Based Real-Time SIEM Dashboard

A security monitoring project that monitors Windows logs with Splunk, detects events using SPL queries and custom rules, sends Telegram notifications, and features a live React dashboard.

---

## Architecture

```
Windows Event Logs → Splunk Enterprise → Alert (Webhook) → Node.js Backend → React Dashboard
                                                                         ↓
                                                                  Telegram Bot
```

---

### 1- BRUTE FORCE 

# A. Writing a Brute Force Rule with Sigma

We write the Brute Force detection rule — already created in the Rules folder — in Sigma format. We then convert this rule to Splunk format. Sigma automatically generates a Splunk query for us. We will later use this query in the Splunk system for log detection and alert generation.

Click the link to access the rule file.
- [Sigma Rule (YML Format)](../Rules/brute-force.yml) 👈 

# B. Simulating a Brute Force Attack with PowerShell for Testing

We run PowerShell as administrator. We then simulate a fake brute force attack with the command below, targeting Splunk which monitors Windows logs.

![splunk alert config](../screenshots/splunk-bruteforce-2.png?v=2)

# C. Log Verification in Splunk

It's time to use the converted Splunk query. We paste the converted query into the Search Bar in Splunk's Search & Reporting section. The test confirms that the brute force log has been ingested into Splunk. We can capture this log either as an alert or as a chart on a Dashboard we create inside Splunk.

![backend webhook code](../screenshots/splunk-bruteforce-1.png?v=2)

# D. Splunk Dashboard 
We can track the brute force attack performed against the user "HackerTurkoglu" on the Dashboard we created in Splunk using a Pie Chart. This chart lets us monitor the number of attacks against each user.

![sigma rule](../screenshots/splunk-bruteforce-3.png?v=2)



# E. Telegram Notification

Instant notifications arriving through the bot we configured with Express in the Telegram application.

![splunk search results](../screenshots/splunk-bruteforce-4.png?v=2)


---

### 2- SUSPICIOUS POWERSHELL COMMAND

# A. Writing the Rule with Sigma

We write a rule with Sigma to detect suspicious PowerShell commands and convert it to Splunk query format.

The reason we want to catch certain suspicious commands in the rule:
- `-enc` flag: Used to Base64-encode and hide the content of a command.
- `-w hidden` flag: The script runs in the background and is not shown to the user in any window.

Click the link to access the rule file.
- [Sigma Rule (YML Format)](../Rules/suspicious-command.yml) 👈 


# B. Testing the Rule

We intentionally run a test via PowerShell to validate the rule we wrote.

![Testing Rule](../screenshots/splunk-ps-1.png?v=2)


# C. Log Verification in Splunk

After running the test, we search in Splunk Search using our converted query.

![Splunk Search](../screenshots/splunk-ps-2.png?v=2)

We observe that our query also produces false positives (noise) from standard Windows processes:

![Splunk Search](../screenshots/splunk-ps-3.png?v=2)

Therefore, we need to add exclusions to both the Sigma rule and the Splunk query to address this:

```
filter_driverstore:
    ParentProcessName|contains:
      - '\DriverStore\FileRepository\'
      - '\Windows\System32\msiexec.exe'
      - '\Windows\SoftwareDistribution\'
``` 

With `filter_driverstore`, if the parent process (ParentProcessName) that spawned this suspicious-looking PowerShell process originates from the driver store (DriverStore), Windows Installer (msiexec.exe), or the Windows Update (SoftwareDistribution) folder, we say "This is the system's own business — leave it alone."

NOTE: Suppose an attacker has infiltrated the system and somehow injected code into the msiexec.exe (Windows Installer) process. If the attacker launches a PowerShell payload through this "trusted-looking" msiexec.exe, our rule will be caught by the filter and will not generate an alert.

See: 
MITRE ATT&CK
T1218.007 — Signed Binary Proxy Execution: Msiexec
T1055 — Process Injection

As a countermeasure: every detection rule has a filter vs. coverage trade-off. Filtering msiexec reduces false positives but opens the T1218.007 defense evasion vector. That's why Sentryfy uses a defense-in-depth approach:

Layer 1: Process creation (4688) — filtered, low noise  
Layer 2: Process injection (Sysmon 8/10) — unfiltered, catches injection  
Layer 3: Parent chain correlation — detects abnormal parent-of-parent relationships


After updating our Splunk query to match the updated rule, we re-verify the logs and observe that the false positive alerts have disappeared.

![Splunk Search](../screenshots/splunk-ps-4.png?v=2) 



### 3- UNAUTHORIZED USB DEVICE CONNECTED

We write a rule to generate alerts when unknown USB devices are connected to the system.

# A. Writing the Rule with Sigma

Click the link to access the rule file.
- [Sigma Rule (YML Format)](../Rules/unauthorize_usb.yml) 👈 


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

- [Sigma Rule (YML Format)](../Rules/brute-force.yml) 👈 


# 4- USB-Originating Threat Detection (Risk-Based Scoring)

Since correlation rules are not compatible with Sigma format, we will implement this type of rule directly as a Splunk query.

This rule is designed to detect suspicious processes triggered shortly after a USB device is connected to the system, and to analyze the threat level of these processes using Risk-Based Alerting (RBA).

---
# A. Writing the Splunk Query

- [Splunk SPL](../Rules/Splunk-SPL/usb-threat-detection.spl) 👈 


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


### 5- USB HID (KEYBOARD) DETECTION — BADUSB 

"This rule is designed to detect Rubber Ducky/BadUSB attacks (MITRE T1200) that exploit the operating system's blind trust in peripherals by emulating HID (Human Interface Device) behavior."

A normal user does not plug in a new keyboard every day at work. If a new device suddenly appears in the HIDClass or Keyboard class on a machine, there are two possibilities:

  1- The user's keyboard broke and they plugged in a new one. (False Positive)
  2- Someone plugged that sneaky Rubber Ducky into the machine and is currently injecting commands into your PowerShell at 1000 words per second. (Critical Attack)

# A. Writing the Splunk Query

One important thing to keep in mind when writing this rule is to whitelist our own mouse and keyboard devices. Otherwise, we will be flooded with false positive alerts.

- [Splunk SPL](../Rules/Splunk-SPL/usb-hid-detection.spl) 👈


# B. Log Verification in Splunk

![Splunk Search](../screenshots/splunk-usb-5.png?v=2)


### 6- WINDOWS DEFENDER TAMPERING ATTEMPT (T1562.001)

When attackers infiltrate a system, the first thing they do is disable Windows Defender to avoid detection. This rule will capture, in real time, any action taken to disable Defender.

# A. Writing the Splunk Query

- [Splunk SPL](../Rules/Splunk-SPL/win-defender.spl) 👈


# B. Log Verification in Splunk

![Splunk Search](../screenshots/splunk-defender-1.png?v=2)


### 7- EVENT LOG CLEARING (T1070.001)

One of the most common techniques attackers use is clearing logs to avoid leaving traces. We therefore need to detect this action as well.

# A. Writing the Splunk Query

- [Splunk SPL](../Rules/Splunk-SPL/event-log-clearing.spl) 👈


# B. Log Verification in Splunk

![Splunk Search](../screenshots/splunk-event-log-1.png?v=2)



### 8- ACCOUNT MANIPULATION (T1098)

In this attack type, the attacker modifies existing user accounts on the system or establishes persistence through newly created accounts.

# A. Writing the Splunk Query

Noise Suppression: Excluding service accounts with `$$` and standard users like SYSTEM is critical. This is where we silence the vast majority of false positives.

Group Filter: We use `where` to exclude insignificant groups such as Users or None, preventing alert fatigue.

- [Splunk SPL](../Rules/Splunk-SPL/account-manipulation.spl) 👈


# B. Log Verification in Splunk

![Splunk Search](../screenshots/splunk-account-1.png?v=2)



### 9- SCHEDULED TASK CREATION (T1053.005)

This rule detects scheduled tasks created with suspicious command patterns 
typically used by attackers to maintain persistence on a compromised host.

It monitors both EventID 4698 (Task Created) and EventID 4688 
(`schtasks.exe /create`) and applies a weighted scoring model based on 
indicators like PowerShell with encoded commands, hidden window flags, 
LOLBAS binaries (rundll32, mshta), and execution from temp or web paths.

This matters because scheduled tasks are one of the most common persistence 
techniques in real-world intrusions — attackers use them to survive reboots 
and execute payloads under SYSTEM privileges. Catching the technique itself 
provides coverage regardless of the specific malware family or framework used.

# A. Writing the Splunk Query

- [Splunk SPL](../Rules/Splunk-SPL/scheduled-task.spl) 👈

# B. Testing the Rule

We run PowerShell as administrator. We then simulate a fake scheduled task with the command below, targeting Splunk which monitors Windows logs.


![Testing Rule](../screenshots/splunk-task-1.png?v=2)

# C. Log Verification in Splunk

![Splunk Search](../screenshots/splunk-task-2.png?v=2)


### 10 - SVCHOST.EXE PROCESS MASQUERADING (T1036.003)

This rule detects svchost.exe (Service Host) execution patterns that deviate from the Windows baseline, indicating potential process masquerading or hollowing.

It monitors Sysmon EventID 1 (Process Creation) to identify instances where svchost.exe runs outside of its legitimate paths (System32 or SysWOW64), lacks the mandatory -k parameter, or is spawned by suspicious parent processes like explorer.exe, cmd.exe, or powershell.exe.

This matters because svchost.exe is one of the most common targets for attackers to hide their presence. By blending in with dozens of legitimate host processes, malware can evade basic detection. Monitoring the "holy trinity" of this process — Path, Parent, and Command Line — allows us to catch sophisticated threats that rely on name-spoofing to maintain a foothold.

# A. Writing the Splunk Query

- [Splunk SPL](../Rules/Splunk-SPL/svchost.spl) 👈

# B. Testing the Rule

To simulate this technique, we trigger a "suspicious" svchost instance by copying the legitimate binary to a temporary folder and executing it without parameters. This violates the path, parent, and command-line logic simultaneously.

![Testing Rule](../screenshots/splunk-svchost-1.png?v=2)


# C. Log Verification in Splunk

![Splunk Search](../screenshots/splunk-svchost-2.png?v=2)


### 11- LSA PROTECTION (PPL) DISABLEMENT (T1562.001)

This rule detects unauthorized modifications to the Windows Registry aimed at disabling LSA (Local Security Authority) Protection.

It monitors Registry EventID 13 (Value Set) specifically targeting the RunAsPPL registry key. When this value is set to 0, it effectively disables the Protected Process Light (PPL) mechanism for LSASS, allowing attackers to perform credential dumping from memory using tools like Mimikatz or PPLDump.

This matters because LSA Protection is a critical defense-in-depth feature. Disabling it is a clear indicator of Impair Defenses (T1562), usually occurring right before an attacker attempts to harvest clear-text passwords or NTLM hashes to move laterally across the network.

# A. Writing the Splunk Query

- [Splunk SPL](../Rules/Splunk-SPL/ppl-disabled.spl) 👈


# B. Testing the Rule

To simulate this defense evasion technique, we manually modify the registry to disable LSA protection. This requires administrative privileges and will trigger a Registry Object Value Set event.

![Testing Rule](../screenshots/ppl-disabled-2.png?v=2)

# C. Log Verification in Splunk

Once the registry key is modified, Splunk will capture the event. The Details field will show DWORD (0x00000000), and our query will flag the action as PPL_DISABLED. This should be treated as a high-severity alert, as it directly precedes credential theft.

![Splunk Search](../screenshots/ppl-disabled-1.png?v=2)


### 12- REMOTE THREAD INJECTION (T1055.002)

This rule detects Process Injection attempts where an external process creates a new thread in a remote process's memory space. This is a common technique used by malware to execute code under the context of a legitimate process to bypass security controls and hide its activity.It monitors Sysmon EventID 8 (CreateRemoteThread). The detection logic focuses on suspicious source processes—specifically those running from non-standard or user-writable directories—attempting to inject code into common targets like notepad.exe. This behavior is highly indicative of DLL injection or reflective loading.  This matters because process injection allows an attacker to live off the land (LotL), inheriting the privileges and trust of the target process. By injecting into a stable process like Notepad, an attacker can maintain persistence and evade detection by basic process-monitoring tools that only look for new, suspicious binaries.

# A. Writing the Splunk Query

This query filters for remote thread creation events where the target is notepad.exe and the source process is NOT located in the trusted System32 or SysWOW64 directories. 

- [Splunk SPL](../Rules/Splunk-SPL/dll-injection.spl) 👈


# B. Testing the Rule

To test this rule, we use a C# based SimpleInjector. The injector follows these steps: 

    Obtains a handle to the target process (notepad.exe) via OpenProcess.  
    Allocates memory in the target process using VirtualAllocEx.  
    Writes the path of the malicious DLL into that memory via WriteProcessMemory.  
    Executes the DLL by calling CreateRemoteThread pointing to LoadLibraryW in kernel32.dll.

- [DLL Injection](../payload/dll-injection.cs) 


# C. Log Verification in Splunk

Upon successful execution, Sysmon will generate an Event ID 8. In the Splunk results:

![Splunk Search](../screenshots/dll-injection.png?v=2)


### 13- PROCESS HOLLOWING (TRANSACTED HOLLOWING) (T1055.012)

This rule detects Process Hollowing attempts specifically utilizing Transactional NTFS (TxF). In this advanced variation, an attacker creates an NTFS transaction, writes a malicious payload into it, and then maps that transaction into the memory space of a legitimate process.

It monitors Sysmon EventID 10 (ProcessAccess) and EventID 1 (Process Creation) to identify suspicious handles being opened with high-privilege access masks (like 0x1F1FFF) shortly after a process is spawned in a suspended state. This technique allows malicious code to run under the guise of a trusted system process while the "real" malicious file never truly exists on the disk in a permanent state.

This matters because Transacted Hollowing is a premier Defense Evasion technique. By leveraging transactions, the malware avoids leaving a footprint that file-based scanners can pick up. Catching this requires monitoring process memory access patterns and the specific sequence of API calls (like CreateProcess followed by NtCreateSection on a transaction) that define the "hollowing" behavior.


# A. Writing Splunk Query

This query looks for processes that are being accessed with suspiciously high privileges by an external source, which is a key indicator that a remote process is attempting to "hollow out" the target.

- [Splunk SPL](../Rules/Splunk-SPL/process-hollowing.spl) 👈

# B. Testing the Rule 

To simulate this technique, we use the transacted_hollowing tool. This utility creates a transaction, writes the payload, and hollows out a target process (like calc.exe).

Execution Steps:

    Run the tool in a test environment to initiate the hollowing process.
    Note the PID of the newly created (hollowed) process.

- [Process Hollowing](../screenshots/hollowing-1.png?v=2)

    Verify the process is active in Task Manager by searching for the corresponding PID. Although it looks like a legitimate process, it is executing the injected payload

- [Process Hollowing](../screenshots/hollowing-2.png?v=2)


# C. Log Verification in Splunk

- [Splunk SPL](../screenshots/hollowing-3.png?v=2)


### 14 - EARLY BIRD APC INJECTION (T1055.004)

This rule detects Early Bird APC (Asynchronous Procedure Call) Injection attempts. This is an advanced process injection technique where an attacker spawns a legitimate process in a suspended state, allocates memory, writes a payload, and queues an APC to the main thread before the process fully initializes.

It monitors Sysmon EventID 10 (ProcessAccess), specifically looking for suspicious source processes (outside of standard system directories) requesting broad access rights (like 0x1FFFFF or 0x1F0FFF). A critical indicator is the presence of *UNKNOWN* in the CallTrace field, which points to code executing from unbacked, dynamically allocated memory segments.

This matters because Early Bird is designed to execute malicious code before AV/EDR products can fully hook the process and establish user-land monitoring. By running the payload right when the thread is resumed, the attacker gets a head start. Catching the anomalous handle requests and unknown call traces is crucial for stopping this early execution phase.

# A. Writing Splunk Query 

- [Splunk SPL](../Rules/Splunk-SPL/early-bird.spl) 👈


# B. Testing the Rule 

To test this, we use a custom injector written in C#. The script uses CreateProcess with the CREATE_SUSPENDED flag (0x00000004) to spawn notepad.exe. It then writes a dummy payload into the process memory, calls QueueUserAPC to hijack the thread, and finally wakes it up with ResumeThread

- [Early Bird APC](../payload/early-bird.cs)

When executed in our test environment from a temporary directory, the terminal confirms the successful suspension, memory allocation, APC queuing, and resumption of the target process.

- [Splunk SPL](../screenshots/early-bird-1.png?v=2)

# C. Log Verification in Splunk

In the Splunk dashboard, the query successfully catches the Event ID 10 log. We can clearly see our early-bird.exe requesting 0x1fffff access to the legitimate Notepad process, with the CallTrace ending in UNKNOWN(00007FFF38C00C91), perfectly confirming the unbacked memory execution anomaly.

- [Splunk SPL](../screenshots/early-bird-2.png?v=2)