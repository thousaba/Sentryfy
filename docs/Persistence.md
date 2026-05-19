### PERSISTENCE (T0003)

---
### 8- ACCOUNT MANIPULATION (T1098)

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
### 9- SCHEDULED TASK (T1053.005)

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

- [Splunk SPL](../Rules/Splunk-SPL/Persistence/scheduled-task.spl) 👈

# B. Testing the Rule

We run PowerShell as administrator. We then simulate a fake scheduled task with the command below, targeting Splunk which monitors Windows logs.


![Testing Rule](../screenshots/splunk-task-1.png?v=2)

# C. Log Verification in Splunk

![Splunk Search](../screenshots/splunk-task-2.png?v=2)


### BROWSER EXTENSIONS (1176)
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
