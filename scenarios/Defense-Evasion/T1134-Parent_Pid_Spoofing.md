# ACCESS TOKEN MANIPULATION: PARENT PID SPOOFING (T1134.004)

This rule detects Parent PID Spoofing, a defense evasion technique where an attacker explicitly assigns a different parent process to a new process using the UpdateProcThreadAttribute API. By making a malicious shell appear as a child of a trusted process like explorer.exe, attackers can bypass parent-child lineage analysis and blend into legitimate system activity.

This matters because most automated detection rules and SOC analysts trust processes spawned by explorer.exe. Spoofing this relationship allows malware to "hide in plain sight," evading simple behavior-based alerts that flag suspicious parents (like a web server or an office app) spawning shells.

# A. Writing the Splunk Query

This query monitors for common shells (cmd.exe, powershell.exe) being spawned by parents that usually don't initiate them in a standard user context, or where the process lineage looks manually manipulated.

- [Splunk SPL](../../Rules/Splunk-SPL/Defense-Evasion/ppid-spoof.spl) 👈


# B. Testing the Rule 

To simulate this technique, we use a custom C# payload that targets the explorer.exe process. The injector performs the following steps:

    Locates the PID of a running explorer.exe instance.

    Opens a handle to the parent process with PROCESS_CREATE_PROCESS (0x0080) privileges.

    Initializes a thread attribute list and uses UpdateProcThreadAttribute with the PROC_THREAD_ATTRIBUTE_PARENT_PROCESS flag (0x00020000) to set the spoofed parent.

    Launches cmd.exe using CreateProcess with the EXTENDED_STARTUPINFO_PRESENT flag (0x00080000).

- [PPID Spoof](../../payload/ppid-spoof.cs)

When run in the test environment, the terminal confirms that explorer.exe (PID 7572) was successfully targeted as the "fake parent" for the new cmd.exe instance (PID 8128). 

![PPID Spoof](../../screenshots/ppid-spoof-1.png?v=2)


# C. Log Verification in Splunk

The detection of PPID Spoofing is a cat-and-mouse game. While the operating system is tricked into believing the spoofed lineage, we can identify anomalies by looking at the execution context and correlating different metadata.

C.1- Verification of Successful Spoofing

  By querying Sysmon EventID 1 for the specific PID generated during our test (PID 8128), we can confirm that the spoofing was successful. Splunk shows cmd.exe as the Image and C:\Windows\explorer.exe as the ParentImage, matching our intended "fake parent"

![Splunk Search](../../screenshots/ppid-spoof-2.png?v=2)

C.2- Identifying the Anomaly

  To catch this "invisible" attack, we apply a more granular logic. Even if the parent is explorer.exe, certain indicators remain suspicious:

    CurrentDirectory Discrepancy: A standard shell spawned by Explorer usually starts in the user's home or system directory. Seeing cmd.exe running from C:\temp_test\ while claimed to be spawned by Explorer is a major red flag.

    Command Line Analysis: Attackers often use simple command lines for initial stagers. By filtering for short, standard command lines that don't match typical Explorer behavior, we can highlight potential spoofing

![Splunk Search](../../screenshots/ppid-spoof-3.png?v=2)

