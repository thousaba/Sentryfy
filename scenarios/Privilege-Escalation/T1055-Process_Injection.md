# PROCESS INJECTION (T1055)
# Sub-Technique: Process Injection: Remote Thread Injection (T1055.002)
This rule detects Process Injection attempts where an external process creates a new thread in a remote process's memory space. This is a common technique used by malware to execute code under the context of a legitimate process to bypass security controls and hide its activity.It monitors Sysmon EventID 8 (CreateRemoteThread). The detection logic focuses on suspicious source processes—specifically those running from non-standard or user-writable directories—attempting to inject code into common targets like notepad.exe. This behavior is highly indicative of DLL injection or reflective loading.  This matters because process injection allows an attacker to live off the land (LotL), inheriting the privileges and trust of the target process. By injecting into a stable process like Notepad, an attacker can maintain persistence and evade detection by basic process-monitoring tools that only look for new, suspicious binaries.

# A. Writing the Splunk Query

This query filters for remote thread creation events where the target is notepad.exe and the source process is NOT located in the trusted System32 or SysWOW64 directories. 

- [Splunk SPL](../../Rules/Splunk-SPL/Privilege-Escalation/dll-injection.spl) 👈


# B. Testing the Rule

To test this rule, we use a C# based SimpleInjector. The injector follows these steps: 

    Obtains a handle to the target process (notepad.exe) via OpenProcess.  
    Allocates memory in the target process using VirtualAllocEx.  
    Writes the path of the malicious DLL into that memory via WriteProcessMemory.  
    Executes the DLL by calling CreateRemoteThread pointing to LoadLibraryW in kernel32.dll.

- [DLL Injection](../../payload/dll-injection.cs) 


# C. Log Verification in Splunk

Upon successful execution, Sysmon will generate an Event ID 8. In the Splunk results:

![Splunk Search](../../screenshots/dll-injection.png?v=2)



---
### TECHNIQUE: PROCESS INJECTION (T1055)
# Sub-Technique : Process Hollowing (Transacted Hollowing) (T1055.012)

This rule detects Process Hollowing attempts specifically utilizing Transactional NTFS (TxF). In this advanced variation, an attacker creates an NTFS transaction, writes a malicious payload into it, and then maps that transaction into the memory space of a legitimate process.

It monitors Sysmon EventID 10 (ProcessAccess) and EventID 1 (Process Creation) to identify suspicious handles being opened with high-privilege access masks (like 0x1F1FFF) shortly after a process is spawned in a suspended state. This technique allows malicious code to run under the guise of a trusted system process while the "real" malicious file never truly exists on the disk in a permanent state.

This matters because Transacted Hollowing is a premier Defense Evasion technique. By leveraging transactions, the malware avoids leaving a footprint that file-based scanners can pick up. Catching this requires monitoring process memory access patterns and the specific sequence of API calls (like CreateProcess followed by NtCreateSection on a transaction) that define the "hollowing" behavior.


# A. Writing Splunk Query

This query looks for processes that are being accessed with suspiciously high privileges by an external source, which is a key indicator that a remote process is attempting to "hollow out" the target.

- [Splunk SPL](../../Rules/Splunk-SPL/Privilege-Escalation/process-hollowing.spl) 👈

# B. Testing the Rule 

To simulate this technique, we use the transacted_hollowing tool. This utility creates a transaction, writes the payload, and hollows out a target process (like calc.exe).

Execution Steps:

    Run the tool in a test environment to initiate the hollowing process.
    Note the PID of the newly created (hollowed) process.

![Process Hollowing](../../screenshots/hollowing-1.png?v=2)

    Verify the process is active in Task Manager by searching for the corresponding PID. Although it looks like a legitimate process, it is executing the injected payload

![Process Hollowing](../../screenshots/hollowing-2.png?v=2)


# C. Log Verification in Splunk

![Splunk SPL](../../screenshots/hollowing-3.png?v=2)


---
### PROCESS INJECTION (T1055)
# Sub-Technique: Process Injection: Asynchronous Procedure Call (T1055.004)

This rule detects Early Bird APC (Asynchronous Procedure Call) Injection attempts. This is an advanced process injection technique where an attacker spawns a legitimate process in a suspended state, allocates memory, writes a payload, and queues an APC to the main thread before the process fully initializes.

It monitors Sysmon EventID 10 (ProcessAccess), specifically looking for suspicious source processes (outside of standard system directories) requesting broad access rights (like 0x1FFFFF or 0x1F0FFF). A critical indicator is the presence of *UNKNOWN* in the CallTrace field, which points to code executing from unbacked, dynamically allocated memory segments.

This matters because Early Bird is designed to execute malicious code before AV/EDR products can fully hook the process and establish user-land monitoring. By running the payload right when the thread is resumed, the attacker gets a head start. Catching the anomalous handle requests and unknown call traces is crucial for stopping this early execution phase.

# A. Writing Splunk Query 

- [Splunk SPL](../../Rules/Splunk-SPL/Privilege-Escalation/early-bird.spl) 👈


# B. Testing the Rule 

To test this, we use a custom injector written in C#. The script uses CreateProcess with the CREATE_SUSPENDED flag (0x00000004) to spawn notepad.exe. It then writes a dummy payload into the process memory, calls QueueUserAPC to hijack the thread, and finally wakes it up with ResumeThread

- [Early Bird APC](../../payload/early-bird.cs)

When executed in our test environment from a temporary directory, the terminal confirms the successful suspension, memory allocation, APC queuing, and resumption of the target process.

![Splunk SPL](../../screenshots/early-bird-1.png?v=2)

# C. Log Verification in Splunk

In the Splunk dashboard, the query successfully catches the Event ID 10 log. We can clearly see our early-bird.exe requesting 0x1fffff access to the legitimate Notepad process, with the CallTrace ending in UNKNOWN(00007FFF38C00C91), perfectly confirming the unbacked memory execution anomaly.

![Splunk SPL](../../screenshots/early-bird-2.png?v=2)
