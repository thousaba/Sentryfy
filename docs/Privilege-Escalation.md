### PRIVILEGE ESCALATION (T0004)

---
### TECHNIQUE: PROCESS INJECTION (T1055)
# Sub-Technique: Process Injection: Remote Thread Injection (T1055.002)
This rule detects Process Injection attempts where an external process creates a new thread in a remote process's memory space. This is a common technique used by malware to execute code under the context of a legitimate process to bypass security controls and hide its activity.It monitors Sysmon EventID 8 (CreateRemoteThread). The detection logic focuses on suspicious source processes—specifically those running from non-standard or user-writable directories—attempting to inject code into common targets like notepad.exe. This behavior is highly indicative of DLL injection or reflective loading.  This matters because process injection allows an attacker to live off the land (LotL), inheriting the privileges and trust of the target process. By injecting into a stable process like Notepad, an attacker can maintain persistence and evade detection by basic process-monitoring tools that only look for new, suspicious binaries.

# A. Writing the Splunk Query

This query filters for remote thread creation events where the target is notepad.exe and the source process is NOT located in the trusted System32 or SysWOW64 directories. 

- [Splunk SPL](../Rules/Splunk-SPL/Privilege-Escalation/dll-injection.spl) 👈


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



---
### TECHNIQUE: PROCESS INJECTION (T1055)
# Sub-Technique : Process Hollowing (Transacted Hollowing) (T1055.012)

This rule detects Process Hollowing attempts specifically utilizing Transactional NTFS (TxF). In this advanced variation, an attacker creates an NTFS transaction, writes a malicious payload into it, and then maps that transaction into the memory space of a legitimate process.

It monitors Sysmon EventID 10 (ProcessAccess) and EventID 1 (Process Creation) to identify suspicious handles being opened with high-privilege access masks (like 0x1F1FFF) shortly after a process is spawned in a suspended state. This technique allows malicious code to run under the guise of a trusted system process while the "real" malicious file never truly exists on the disk in a permanent state.

This matters because Transacted Hollowing is a premier Defense Evasion technique. By leveraging transactions, the malware avoids leaving a footprint that file-based scanners can pick up. Catching this requires monitoring process memory access patterns and the specific sequence of API calls (like CreateProcess followed by NtCreateSection on a transaction) that define the "hollowing" behavior.


# A. Writing Splunk Query

This query looks for processes that are being accessed with suspiciously high privileges by an external source, which is a key indicator that a remote process is attempting to "hollow out" the target.

- [Splunk SPL](../Rules/Splunk-SPL/Privilege-Escalation/process-hollowing.spl) 👈

# B. Testing the Rule 

To simulate this technique, we use the transacted_hollowing tool. This utility creates a transaction, writes the payload, and hollows out a target process (like calc.exe).

Execution Steps:

    Run the tool in a test environment to initiate the hollowing process.
    Note the PID of the newly created (hollowed) process.

![Process Hollowing](../screenshots/hollowing-1.png?v=2)

    Verify the process is active in Task Manager by searching for the corresponding PID. Although it looks like a legitimate process, it is executing the injected payload

![Process Hollowing](../screenshots/hollowing-2.png?v=2)


# C. Log Verification in Splunk

![Splunk SPL](../screenshots/hollowing-3.png?v=2)


---
### PROCESS INJECTION (T1055)
# Sub-Technique: Process Injection: Asynchronous Procedure Call (T1055.004)

This rule detects Early Bird APC (Asynchronous Procedure Call) Injection attempts. This is an advanced process injection technique where an attacker spawns a legitimate process in a suspended state, allocates memory, writes a payload, and queues an APC to the main thread before the process fully initializes.

It monitors Sysmon EventID 10 (ProcessAccess), specifically looking for suspicious source processes (outside of standard system directories) requesting broad access rights (like 0x1FFFFF or 0x1F0FFF). A critical indicator is the presence of *UNKNOWN* in the CallTrace field, which points to code executing from unbacked, dynamically allocated memory segments.

This matters because Early Bird is designed to execute malicious code before AV/EDR products can fully hook the process and establish user-land monitoring. By running the payload right when the thread is resumed, the attacker gets a head start. Catching the anomalous handle requests and unknown call traces is crucial for stopping this early execution phase.

# A. Writing Splunk Query 

- [Splunk SPL](../Rules/Splunk-SPL/Privilege-Escalation/early-bird.spl) 👈


# B. Testing the Rule 

To test this, we use a custom injector written in C#. The script uses CreateProcess with the CREATE_SUSPENDED flag (0x00000004) to spawn notepad.exe. It then writes a dummy payload into the process memory, calls QueueUserAPC to hijack the thread, and finally wakes it up with ResumeThread

- [Early Bird APC](../payload/early-bird.cs)

When executed in our test environment from a temporary directory, the terminal confirms the successful suspension, memory allocation, APC queuing, and resumption of the target process.

![Splunk SPL](../screenshots/early-bird-1.png?v=2)

# C. Log Verification in Splunk

In the Splunk dashboard, the query successfully catches the Event ID 10 log. We can clearly see our early-bird.exe requesting 0x1fffff access to the legitimate Notepad process, with the CallTrace ending in UNKNOWN(00007FFF38C00C91), perfectly confirming the unbacked memory execution anomaly.

![Splunk SPL](../screenshots/early-bird-2.png?v=2)


---
### TECHNIQUE: EXPLOITATION FOR PRIVILEGE ESCALATION (T1068) : BRING YOUR OWN VULNERABLE DRIVER (BYOVD)

This rule detects Bring Your Own Vulnerable Driver (BYOVD) attacks, a privilege escalation and defense evasion technique where an attacker drops a legitimately signed but known-vulnerable kernel driver (like Micro-Star's RTCore64.sys or Capcom's capcom.sys) onto the target system.

It monitors EventID 7045 (Service/Driver Installation) and correlates it with EventID 7000 (Service Control Manager Errors). The custom Splunk logic specifically looks for drivers that are successfully installed but fail to start due to OS-level protections like Microsoft's Vulnerable Driver Blocklist (HVCI/Memory Integrity).

This matters because attackers use BYOVD to gain Ring 0 (Kernel-level) execution. Once in the kernel, they can blindly terminate EDR agents, unhook user-mode APIs, and mask their malware. Even if Windows blocks the driver from starting, the mere attempt to install a known vulnerable driver is a massive red flag that a sophisticated adversary is present on the endpoint.

# A. Writing Splunk Query

- [Splunk SPL](../Rules/Splunk-SPL/Privilege-Escalation/byovd.spl) 👈


# B. Testing the Rule

To simulate this attack, we first ensure that Microsoft's Vulnerable Driver Blocklist is enabled in Windows Security settings.

![BYOVD](../screenshots/byovd-1.png?v=2)

Next, we download an old, highly exploitable driver named RTCore64.sys (originally part of MSI Afterburner) and attempt to load it into the system by creating and starting a new service. Windows Defender's kernel protection intervenes and blocks the driver from executing due to its revoked certificate/known malicious hash. However, this failed attempt is exactly what we need to trace the attacker's footprint.

![BYOVD](../screenshots/byovd-2.png?v=2)

# C. Log Verification in Splunk

By running our query, we correlate the installation event with the subsequent failure. The Splunk dashboard clearly shows the RTCore64.sys driver path and catches the specific 2148204812 error code (which translates to an invalid or blocked certificate signature). Our custom logic flags this precisely as PREVENTED: BYOVD Attack Blocked (Revoked Cert) under the Sentryfy_Alert column.

![Splunk Search](../screenshots/byovd-3.png?v=2)


---
### TECHNIQUE: ABUSE ELEVATION CONTROL MECHANISM: BYPASS USER ACCOUNT CONTROL (T1548.002)

This rule detects UAC (User Account Control) Bypass attempts utilizing the fodhelper.exe binary. fodhelper.exe is a trusted Windows binary that auto-elevates (runs with High Integrity without prompting the user) and looks for specific registry keys to execute commands during its run.

It monitors both Sysmon EventID 1 (Process Creation) and EventIDs 12, 13, 14 (Registry Events). The detection logic is two-fold: first, it catches the attacker modifying the HKCU\Software\Classes\ms-settings\Shell\Open\command registry key (the preparation phase), and second, it catches fodhelper.exe unexpectedly spawning a child process like cmd.exe or powershell.exe (the execution phase).

This matters because bypassing UAC is a critical step for an attacker moving from a standard user context to Administrator (High Integrity). By hijacking the execution flow of an auto-elevating binary, they avoid popping up the UAC consent prompt to the user, allowing silent privilege escalation.

# A. Writing Splunk Query

- [Splunk SPL](../Rules/Splunk-SPL/Privilege-Escalation/uac-bypass.spl) 👈

# B. Testing the Rule

To simulate this UAC bypass, we manually manipulate the registry to hijack fodhelper's execution path. We set the DelegateExecute value to null (which bypasses a specific COM check) and set the default value of the command key to our payload (cmd.exe).

![UAC Bypass](../screenshots/uac-bypass-1.png?v=2)

When we run fodhelper.exe, it auto-elevates and immediately launches our payload. As seen in the test environment, a new cmd.exe window pops up, and running whoami /priv or checking the window title confirms it is running with Administrator (High Integrity) privileges

# C. Log Verification in Splunk

The Splunk query beautifully captures both phases of the attack in a single timeline.

    First, the WARNING alerts trigger for EventCode 12 and 13, showing the exact registry modifications made to the ms-settings path.

    Seconds later, the CRITICAL alert triggers for EventCode 1, showing that fodhelper.exe spawned our cmd.exe payload with a High IntegrityLevel.

This dual-layer detection ensures that even if the attacker tries to clean up the registry keys immediately after execution, the behavior is already permanently logged.

![Splunk Search](../screenshots/uac-bypass-2.png?v=2)
