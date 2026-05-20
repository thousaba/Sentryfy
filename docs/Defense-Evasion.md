### DEFENSE EVASION (T0005)

---
### 6- IMPAIR DEFENSES: DISABLE OR MODIFY TOOLS (T1562)
# Sub-Technique: Disable or Modify Tools (T1562.001) 

When attackers infiltrate a system, the first thing they do is disable Windows Defender to avoid detection. This rule will capture, in real time, any action taken to disable Defender.

# A. Writing the Splunk Query

- [Splunk SPL](../Rules/Splunk-SPL/Defense-Evasion/win-defender.spl) 👈


# B. Log Verification in Splunk

![Splunk Search](../screenshots/splunk-defender-1.png?v=2)

---

### 7- TECHNIQUE: INDICATOR REMOVAL ON HOST (T1070)
# Sub-Technique: Indicator Removal on Host: Clear Windows Event Logs (T1070.001)

One of the most common techniques attackers use is clearing logs to avoid leaving traces. We therefore need to detect this action as well.

# A. Writing the Splunk Query

- [Splunk SPL](../Rules/Splunk-SPL/Defense-Evasion/event-log-clearing.spl) 👈


# B. Log Verification in Splunk

![Splunk Search](../screenshots/splunk-event-log-1.png?v=2)


---
### TECHNIQUE: MASQUERADING: PROCESS MASQUERADING (T1036.003)

This rule detects svchost.exe (Service Host) execution patterns that deviate from the Windows baseline, indicating potential process masquerading or hollowing.

It monitors Sysmon EventID 1 (Process Creation) to identify instances where svchost.exe runs outside of its legitimate paths (System32 or SysWOW64), lacks the mandatory -k parameter, or is spawned by suspicious parent processes like explorer.exe, cmd.exe, or powershell.exe.

This matters because svchost.exe is one of the most common targets for attackers to hide their presence. By blending in with dozens of legitimate host processes, malware can evade basic detection. Monitoring the "holy trinity" of this process — Path, Parent, and Command Line — allows us to catch sophisticated threats that rely on name-spoofing to maintain a foothold.

# A. Writing the Splunk Query

- [Splunk SPL](../Rules/Splunk-SPL/Defense-Evasion/svchost.spl) 👈

# B. Testing the Rule

To simulate this technique, we trigger a "suspicious" svchost instance by copying the legitimate binary to a temporary folder and executing it without parameters. This violates the path, parent, and command-line logic simultaneously.

![Testing Rule](../screenshots/splunk-svchost-1.png?v=2)


# C. Log Verification in Splunk

![Splunk Search](../screenshots/splunk-svchost-2.png?v=2)


---

### TECHNIQUE: IMPAIR DEFENSES: DISABLE OR MODIFY TOOLS (T1562)
# Sub-Technique: Disable or Modify Tools (T1562.001)

This rule detects unauthorized modifications to the Windows Registry aimed at disabling LSA (Local Security Authority) Protection.

It monitors Registry EventID 13 (Value Set) specifically targeting the RunAsPPL registry key. When this value is set to 0, it effectively disables the Protected Process Light (PPL) mechanism for LSASS, allowing attackers to perform credential dumping from memory using tools like Mimikatz or PPLDump.

This matters because LSA Protection is a critical defense-in-depth feature. Disabling it is a clear indicator of Impair Defenses (T1562), usually occurring right before an attacker attempts to harvest clear-text passwords or NTLM hashes to move laterally across the network.

# A. Writing the Splunk Query

- [Splunk SPL](../Rules/Splunk-SPL/Defense-Evasion/ppl-disabled.spl) 👈


# B. Testing the Rule

To simulate this defense evasion technique, we manually modify the registry to disable LSA protection. This requires administrative privileges and will trigger a Registry Object Value Set event.

![Testing Rule](../screenshots/ppl-disabled-2.png?v=2)

# C. Log Verification in Splunk

Once the registry key is modified, Splunk will capture the event. The Details field will show DWORD (0x00000000), and our query will flag the action as PPL_DISABLED. This should be treated as a high-severity alert, as it directly precedes credential theft.

![Splunk Search](../screenshots/ppl-disabled-1.png?v=2)


---
### TECHNIQUE: ACCESS TOKEN MANIPULATION: PARENT PID SPOOFING (T1134.004)

This rule detects Parent PID Spoofing, a defense evasion technique where an attacker explicitly assigns a different parent process to a new process using the UpdateProcThreadAttribute API. By making a malicious shell appear as a child of a trusted process like explorer.exe, attackers can bypass parent-child lineage analysis and blend into legitimate system activity.

This matters because most automated detection rules and SOC analysts trust processes spawned by explorer.exe. Spoofing this relationship allows malware to "hide in plain sight," evading simple behavior-based alerts that flag suspicious parents (like a web server or an office app) spawning shells.

# A. Writing the Splunk Query

This query monitors for common shells (cmd.exe, powershell.exe) being spawned by parents that usually don't initiate them in a standard user context, or where the process lineage looks manually manipulated.

- [Splunk SPL](../Rules/Splunk-SPL/Defense-Evasion/ppid-spoof.spl) 👈


# B. Testing the Rule 

To simulate this technique, we use a custom C# payload that targets the explorer.exe process. The injector performs the following steps:

    Locates the PID of a running explorer.exe instance.

    Opens a handle to the parent process with PROCESS_CREATE_PROCESS (0x0080) privileges.

    Initializes a thread attribute list and uses UpdateProcThreadAttribute with the PROC_THREAD_ATTRIBUTE_PARENT_PROCESS flag (0x00020000) to set the spoofed parent.

    Launches cmd.exe using CreateProcess with the EXTENDED_STARTUPINFO_PRESENT flag (0x00080000).

- [PPID Spoof](../payload/ppid-spoof.cs)

When run in the test environment, the terminal confirms that explorer.exe (PID 7572) was successfully targeted as the "fake parent" for the new cmd.exe instance (PID 8128). 

![PPID Spoof](../screenshots/ppid-spoof-1.png?v=2)


# C. Log Verification in Splunk

The detection of PPID Spoofing is a cat-and-mouse game. While the operating system is tricked into believing the spoofed lineage, we can identify anomalies by looking at the execution context and correlating different metadata.

C.1- Verification of Successful Spoofing

  By querying Sysmon EventID 1 for the specific PID generated during our test (PID 8128), we can confirm that the spoofing was successful. Splunk shows cmd.exe as the Image and C:\Windows\explorer.exe as the ParentImage, matching our intended "fake parent"

![Splunk Search](../screenshots/ppid-spoof-2.png?v=2)

C.2- Identifying the Anomaly

  To catch this "invisible" attack, we apply a more granular logic. Even if the parent is explorer.exe, certain indicators remain suspicious:

    CurrentDirectory Discrepancy: A standard shell spawned by Explorer usually starts in the user's home or system directory. Seeing cmd.exe running from C:\temp_test\ while claimed to be spawned by Explorer is a major red flag.

    Command Line Analysis: Attackers often use simple command lines for initial stagers. By filtering for short, standard command lines that don't match typical Explorer behavior, we can highlight potential spoofing

![Splunk Search](../screenshots/ppid-spoof-3.png?v=2)


---

### TECHNIQUE: MASQUERADING: MASQUERADE FILE TYPE (T1036.008) 
This rule detects the Masquerade File Type technique, a sub-technique of Defense Evasion where an attacker manipulates a file's name or extension to make a malicious executable appear as a harmless or unrelated file type (like .db, .dat, or .tmp).

It monitors Security EventID 4688 (Process Creation) and EventID 4698 (Scheduled Task Created). The custom Splunk logic specifically looks for instances where trusted but often abused binaries (like javaw.exe) attempt to execute files from user-writable directories (%Temp% or %AppData%) that have completely non-executable extensions.

This matters because attackers often drop their payloads disguised as database or temporary files to bypass basic AV file-extension scans. When they execute javaw.exe -jar payload.db, the OS doesn't care about the .db extension—it just runs the bytecode. Catching this mismatch between the executing process and the expected file type is a bulletproof way to detect stealthy persistence or execution attempts.

# A. Writing the Splunk Query

- [Splunk SPL](../Rules/Splunk-SPL/Defense-Evasion/masquerade-file-type.spl) 👈

# B. Testing the Rule
To simulate this defense evasion tactic, we mimic an attacker establishing persistence. We create a malicious Scheduled Task named "Java Updater" that uses the legitimate javaw.exe binary to execute a payload. The catch? The payload is hidden in the AppData folder and disguised as a harmless database file (update.db).

# C. Log Verification in Splunk
The Splunk dashboard immediately catches the anomaly. Whether it's the task creation (Event 4698) or the actual execution (Event 4688), the regex perfectly captures javaw.exe trying to run a .db file from the AppData path. The alert is tagged with a high severity, giving the SOC analyst exactly what they need to investigate the masqueraded file.

![Splunk Search](../screenshots/masquerade-file-type.png?v=2)
