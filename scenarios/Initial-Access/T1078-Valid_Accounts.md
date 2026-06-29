# VALID ACCOUNTS (T1078)
This rule detects the use of Valid Accounts, a defense evasion and initial access technique where attackers utilize compromised credentials (local, domain, or cloud) to bypass access controls. Since the adversary logs in acting exactly like a legitimate user, this activity blends seamlessly into normal daily network traffic.

It monitors Security EventID 4648 (A logon was attempted using explicit credentials) and correlates it with suspicious processes like runas.exe. While administrators occasionally use runas for legitimate troubleshooting, an unexpected spike or usage from a standard user context often indicates an attacker pivoting or elevating privileges using a stolen valid account.

This matters because once attackers possess valid credentials, they no longer need to rely on noisy malware or exploits. They simply log in, access data, and move laterally. Detecting this requires hunting for anomalous credential usage—specifically, a user process explicitly supplying credentials to authenticate as a different, higher-privileged account

# A. Writing the Splunk Query
- [Splunk SPL](../../Rules/Splunk-SPL/Initial-Access/valid-accounts.spl) 👈

# B. Testing the Rule
To simulate an attacker leveraging a valid account to escalate privileges locally, we use the built-in Windows runas utility. Assuming the attacker has already dumped or cracked the password for the local or domain Administrator, they use this command to spawn a new command shell running under that high-privileged context.

![Splunk Search](../../screenshots/valid-accounts-1.png?v=2)

# C. Log Verification in Splunk 
By searching for Event ID 4648 in our Splunk dashboard, we can clearly see the exact moment the explicit credentials were used. The log explicitly shows the Tetikleyen_Kullanici (the initial compromised low-privilege shell) and the Ele_Gecirilen_Hesap (the Administrator account the attacker pivoted into). This provides the SOC analyst with immediate visibility into which valid accounts are actively being abused on the endpoint.

![Splunk Search](../../screenshots/valid-accounts-2.png?v=2)