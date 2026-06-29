# MASQUERADING: PROCESS MASQUERADING (T1036.003)

This rule detects svchost.exe (Service Host) execution patterns that deviate from the Windows baseline, indicating potential process masquerading or hollowing.

It monitors Sysmon EventID 1 (Process Creation) to identify instances where svchost.exe runs outside of its legitimate paths (System32 or SysWOW64), lacks the mandatory -k parameter, or is spawned by suspicious parent processes like explorer.exe, cmd.exe, or powershell.exe.

This matters because svchost.exe is one of the most common targets for attackers to hide their presence. By blending in with dozens of legitimate host processes, malware can evade basic detection. Monitoring the "holy trinity" of this process — Path, Parent, and Command Line — allows us to catch sophisticated threats that rely on name-spoofing to maintain a foothold.

# A. Writing the Splunk Query

- [Splunk SPL](../../Rules/Splunk-SPL/Defense-Evasion/svchost.spl) 👈

# B. Testing the Rule

To simulate this technique, we trigger a "suspicious" svchost instance by copying the legitimate binary to a temporary folder and executing it without parameters. This violates the path, parent, and command-line logic simultaneously.

![Testing Rule](../../screenshots/splunk-svchost-1.png?v=2)


# C. Log Verification in Splunk

![Splunk Search](../../screenshots/splunk-svchost-2.png?v=2)

