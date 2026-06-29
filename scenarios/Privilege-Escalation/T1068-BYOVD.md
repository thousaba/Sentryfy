# EXPLOITATION FOR PRIVILEGE ESCALATION (T1068) : BRING YOUR OWN VULNERABLE DRIVER (BYOVD)

This rule detects Bring Your Own Vulnerable Driver (BYOVD) attacks, a privilege escalation and defense evasion technique where an attacker drops a legitimately signed but known-vulnerable kernel driver (like Micro-Star's RTCore64.sys or Capcom's capcom.sys) onto the target system.

It monitors EventID 7045 (Service/Driver Installation) and correlates it with EventID 7000 (Service Control Manager Errors). The custom Splunk logic specifically looks for drivers that are successfully installed but fail to start due to OS-level protections like Microsoft's Vulnerable Driver Blocklist (HVCI/Memory Integrity).

This matters because attackers use BYOVD to gain Ring 0 (Kernel-level) execution. Once in the kernel, they can blindly terminate EDR agents, unhook user-mode APIs, and mask their malware. Even if Windows blocks the driver from starting, the mere attempt to install a known vulnerable driver is a massive red flag that a sophisticated adversary is present on the endpoint.

# A. Writing Splunk Query

- [Splunk SPL](../../Rules/Splunk-SPL/Privilege-Escalation/byovd.spl) 👈


# B. Testing the Rule

To simulate this attack, we first ensure that Microsoft's Vulnerable Driver Blocklist is enabled in Windows Security settings.

![BYOVD](../../screenshots/byovd-1.png?v=2)

Next, we download an old, highly exploitable driver named RTCore64.sys (originally part of MSI Afterburner) and attempt to load it into the system by creating and starting a new service. Windows Defender's kernel protection intervenes and blocks the driver from executing due to its revoked certificate/known malicious hash. However, this failed attempt is exactly what we need to trace the attacker's footprint.

![BYOVD](../../screenshots/byovd-2.png?v=2)

# C. Log Verification in Splunk

By running our query, we correlate the installation event with the subsequent failure. The Splunk dashboard clearly shows the RTCore64.sys driver path and catches the specific 2148204812 error code (which translates to an invalid or blocked certificate signature). Our custom logic flags this precisely as PREVENTED: BYOVD Attack Blocked (Revoked Cert) under the Sentryfy_Alert column.

![Splunk Search](../../screenshots/byovd-3.png?v=2)
