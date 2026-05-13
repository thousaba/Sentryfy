### PERSISTENCE (T0003)

---
### 8- ACCOUNT MANIPULATION (T1098)

In this attack type, the attacker modifies existing user accounts on the system or establishes persistence through newly created accounts.

# A. Writing the Splunk Query

Noise Suppression: Excluding service accounts with `$$` and standard users like SYSTEM is critical. This is where we silence the vast majority of false positives.

Group Filter: We use `where` to exclude insignificant groups such as Users or None, preventing alert fatigue.

- [Splunk SPL](../Rules/Splunk-SPL/Persistence/account-manipulation.spl) 👈


# B. Log Verification in Splunk

![Splunk Search](../screenshots/splunk-account-1.png?v=2)


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
