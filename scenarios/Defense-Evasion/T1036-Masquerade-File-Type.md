# MASQUERADING: MASQUERADE FILE TYPE (T1036.008) 
This rule detects the Masquerade File Type technique, a sub-technique of Defense Evasion where an attacker manipulates a file's name or extension to make a malicious executable appear as a harmless or unrelated file type (like .db, .dat, or .tmp).

It monitors Security EventID 4688 (Process Creation) and EventID 4698 (Scheduled Task Created). The custom Splunk logic specifically looks for instances where trusted but often abused binaries (like javaw.exe) attempt to execute files from user-writable directories (%Temp% or %AppData%) that have completely non-executable extensions.

This matters because attackers often drop their payloads disguised as database or temporary files to bypass basic AV file-extension scans. When they execute javaw.exe -jar payload.db, the OS doesn't care about the .db extension—it just runs the bytecode. Catching this mismatch between the executing process and the expected file type is a bulletproof way to detect stealthy persistence or execution attempts.

# A. Writing the Splunk Query

- [Splunk SPL](../../Rules/Splunk-SPL/Defense-Evasion/masquerade-file-type.spl) 👈

# B. Testing the Rule
To simulate this defense evasion tactic, we mimic an attacker establishing persistence. We create a malicious Scheduled Task named "Java Updater" that uses the legitimate javaw.exe binary to execute a payload. The catch? The payload is hidden in the AppData folder and disguised as a harmless database file (update.db).

# C. Log Verification in Splunk
The Splunk dashboard immediately catches the anomaly. Whether it's the task creation (Event 4698) or the actual execution (Event 4688), the regex perfectly captures javaw.exe trying to run a .db file from the AppData path. The alert is tagged with a high severity, giving the SOC analyst exactly what they need to investigate the masqueraded file.

![Splunk Search](../../screenshots/masquerade-file-type.png?v=2)
