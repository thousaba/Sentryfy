# BROWSER EXTENSIONS (1176)
This rule detects malicious or unauthorized Browser Extensions installed via Windows Registry modifications. Attackers frequently use browser extensions as a stealthy Persistence mechanism to steal credentials, hijack active sessions (cookie theft), monitor web traffic, or bypass Two-Factor Authentication (2FA).

It monitors Sysmon EventIDs 12 and 13 (Registry Object Add/ValueSet) targeting the extension and policy hives for all major browsers (Chrome, Edge, Firefox, Brave, Opera). The custom detection logic identifies the exact installation method, specifically flagging enterprise policy abuse like ExtensionInstallForcelist, which forces an extension to install silently and prevents the user from removing it.

This matters because modern attacks increasingly target the browser rather than the OS. By injecting a malicious extension via registry keys, the attacker ensures their code runs within the trusted context of the browser, easily bypassing traditional network inspection and file-based AV scanning.

# A. Writing the Splunk Query

- [Splunk SPL](../../Rules/Splunk-SPL/Persistence/browser-extensions.spl) 👈

# B. Testing the Rule
To simulate this persistence technique, we use the command line to modify the HKLM registry hive. We inject a registry key that leverages Google Chrome's ExtensionInstallForcelist enterprise policy. This tells Chrome to silently download and install an extension directly from the Google Web Store update URL upon the next launch, securely locking the extension so the local user cannot disable it.

![Testing Rule](../../screenshots/browser-extensions-1.png?v=2)

# C. Verification in Splunk 
The Splunk query successfully intercepts the registry modification. Due to our advanced parsing logic, the raw registry event is beautifully translated into actionable SOC metrics. We immediately see that the Browser is Chrome, the Install_Method is explicitly flagged as Force_Install_Policy, and consequently, the Severity is dynamically set to Critical. The query also neatly extracts the 32-character Extension_ID, which analysts can pivot on to hunt down the exact malicious extension in the environment.

![Splunk Search](../../screenshots/browser-extensions-2.png?v=2)
