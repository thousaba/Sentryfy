# ACCOUNT DISCOVERY (T1087.001) - MSRPC SAMR USER ENUMERATION VIA SMB
This rule detects reconnaissance and discovery activities conducted by an attacker to exfiltrate local user accounts and password policies from the network. Attackers leverage this technique to identify existing accounts before attempting privilege escalation or lateral movement within the target system.

The rule monitors Windows Security EventID 5145 (A network share object was accessed). In scenarios where network traffic monitoring (tshark/Wireshark) is blinded by firewalls or network-level encryption (Encrypted SMB3), this rule captures data directly from the operating system kernel. Even if attackers disguise their tracks behind the legitimate \srvsvc pipe over a valid IPC$ share, our rule specifically pinpoints anomalous and high-velocity requests targeting the RelativeTargetName=samr endpoint.

Catching the attack at its very first step—the discovery phase—is critical. Detecting this enumeration activity before the attacker introduces malware or launches brute-force attacks enables proactive containment by isolating the offending IP address from the network, effectively preventing potential data exfiltration or persistent intrusion attempts.

# A. Writing the Splunk Query

- [Discovery-Account](../Rules/Splunk-SPL/Discovery/local-account-discovery.spl) 👈

# B. Testing the Rule
To simulate this local account discovery technique, a remote query is executed against the target Windows machine from the attacker's Kali Linux machine using the samrdump.py tool from the Impacket framework.

```
impacket-samrdump <username>:<password>@192.168.56.1"
```

# C. Log Verification in Splunk
The Splunk dashboard immediately captures Event ID 5145 generated after activating the Detailed File Share auditing policy. In the search results, we can clearly extract critical forensic evidence: the attacker's Kali IP address (IpAddress), the legitimate user account abused to gain access (SubjectUserName), the targeted critical object (RelativeTargetName=samr), and the millisecond time difference (duration_sec) that proves the use of an automated tool.

![Splunk Search](../screenshots/discovery-local-account.png?v=2)
