### REMOTE ACCESS TOOLS (T1219)
This rule detects the malicious or unauthorized use of legitimate Remote Access Tools (like AnyDesk, TeamViewer, or RustDesk), which are frequently abused by ransomware operators and initial access brokers for Command and Control (C2) and persistent access.

It monitors Sysmon EventID 1 (Process Creation). Because these applications are legitimately signed and widely used by IT departments, simply alerting on their presence causes extreme alert fatigue. To counter this, the detection logic uses a dynamic scoring system: it evaluates whether the tool is executing from a suspicious path (%Temp%, AppData), spawned by a suspicious parent (powershell.exe, cmd.exe), or executed with stealth flags (--silent, --set-password). An alert is only triggered if the combined anomaly score crosses a predefined threshold.

This matters because adversaries rely on these "Living off the Land" (LotL) tools to blend in with normal administrative traffic and bypass EDR solutions. Catching the behavioral anomalies surrounding their execution is the only effective way to distinguish an attacker from a legitimate helpdesk technician.

# A. Writing the Splunk Query

- [Splunk SPL](../Rules/Splunk-SPL/Command-and-Control/remote-access-tools.spl) 👈

# B. Testing the Rule 
To test the robustness of the scoring system, we run a PowerShell script that simulates an attacker deploying AnyDesk. The script copies the legitimate binary to the %TEMP% directory and executes it with silent installation flags. It also runs a baseline test from the normal Program Files directory to ensure legitimate activity doesn't trigger a false positive.

```
Write-Host "[*] Copying AnyDesk to suspicious path..." -ForegroundColor Yellow
Copy-Item "C:\Program Files (x86)\AnyDesk\AnyDesk.exe" "$env:TEMP\AnyDesk.exe" -Force

Write-Host "[*] Test 1: --silent flag (expected: score=3, high)" -ForegroundColor Yellow
& "$env:TEMP\AnyDesk.exe" --silent
Start-Sleep -Seconds 5
Stop-Process -Name AnyDesk -Force -ErrorAction SilentlyContinue

Write-Host "[*] Test 2: --silent --install flags (expected: score=3, high)" -ForegroundColor Yellow
& "$env:TEMP\AnyDesk.exe" --silent --install
Start-Sleep -Seconds 5
Stop-Process -Name AnyDesk -Force -ErrorAction SilentlyContinue

Write-Host "[*] Test 3: Normal execution from Program Files (expected: no alert)" -ForegroundColor Yellow
Start-Process "C:\Program Files (x86)\AnyDesk\AnyDesk.exe"
Start-Sleep -Seconds 5
Stop-Process -Name AnyDesk -Force -ErrorAction SilentlyContinue

Write-Host "[+] Tests complete. Check Splunk for 2 high severity alerts." -ForegroundColor Green
```

# C. Log Verification in Splunk
The Splunk dashboard perfectly validates our logic. The query filters out the legitimate "Test 3" execution but successfully catches the first two malicious simulations. Because the binary was spawned by powershell.exe (suspicious parent), ran from the Temp folder (suspicious path), and used --silent flags, the equation mathematically calculates a score of 3. This appropriately tags the events with a High severity, giving the SOC immediate, high-fidelity context.

![Splunk Search](../screenshots/remote-access-tools-2.png?v=2)


### (T1071.004) DNS TUNNELING (Host-Based / Windows DNS API)
This rule detects DNS Tunneling and Beaconing activities utilized by attackers for covert Command and Control (C2) communications or data exfiltration. Since DNS traffic is almost always permitted outbound through corporate firewalls, threat actors encapsulate non-DNS protocols (such as SSH, HTTP, or raw data chunks) inside encoded, high-length subdomains targeting an attacker-controlled authoritative name server.

The analytic engine monitors Sysmon EventID 22 (DNS Query) and applies entropy/length validation:

    base_domain Extraction: It parses out the core parent domain using regular expressions to group multi-subdomain noise.

    subdomain_len Assessment: It measures the character length of the requested subdomain. Legitimate subdomains rarely exceed 30 random characters, whereas C2 payloads or exfiltrated data streams require massive strings.

    High Cardinality Check (dc(QueryName)): It aggregates requests to find unique subdomains hitting the same base domain in a short window. A high ratio of unique requests indicates data chunks or random C2 heartbeat queries rather than standard infrastructure lookups.

Identifying DNS tunneling early is a critical priority because it represents a highly evasive technique used in advanced persistent threats (APTs). Catching an outbound stream of long, randomized subdomains allows analysts to block malicious external name servers immediately, cutting off the attacker's interactive shell or halting an active data breach before critical assets are fully exfiltrated.

# A. Writing the Splunk Query

- [Splunk SPL](../Rules/Splunk-SPL/Command-and-Control/dns-tunneling.spl) 👈

# B. Testing the Rule
To simulate an active DNS tunneling channel, a looped PowerShell script is executed from the target Windows system. The script dynamically generates 50 high-entropy, randomized 35-character strings mimicking encrypted payload data, appends them to the malicious domain evil-c2.com, and forces outbound resolution lookups directly against a public resolver (8.8.8.8) with brief sleeping intervals.

![testing the rule](../screenshots/dns-tunneling-1.png?v=2)

# C. Log Verification in Splunk
The analytics platform successfully aggregates the behavioral indicators once the baseline criteria are met. As verified in dns-tunneling-2.png, the Splunk results produce an airtight threat classification layout:

    base_domain: Automatically normalizes the inbound lookups down to the root domain (evil-c2.com), screening out localized environmental noise.

    query_count & unique_subs: High volume matching (300 queries to 300 unique records) explicitly proves high-cardinality beaconing or data fragmentation rather than repetitive structural assets lookups.

    avg_len & total_exfil_bytes: Measures active payload weight. The calculation sum(subdomain_len) dynamically tracks the exact volume of data characters smuggled over the wire, giving security analysts a clear indicator of data exfiltration velocity.

    processes & verdict: Flags powershell.exe dynamically through the suspicious_process array. Because an adversarial utility initiated the DNS lookups, the calculation engine heavily penalizes the asset profile, adding a static +50 weighting factor. This instantly escalates the verdict metric to CRITICAL, alerting incident handlers to prioritize triage on DESKTOP-MJ170VE.

    sample_subdomains: Exposes a clean, extracted array of the 35-character randomized strings directly inside the output panel, providing rapid, actionable artifacts for threat intelligence pivot searches.

![Splunk Search](../screenshots/dns-tunneling-2.png?v=2)


### (T1071.004 + T1048.003) DNS TUNNELING (Network-Based + Process Correlation)
This rule correlates network-layer DNS anomalies with endpoint process execution telemetry to detect raw-socket DNS Tunneling activities (such as iodine). Because raw-socket tunnelers bypass the standard Windows DNS subsystem (DnsQuery), host-based DNS logs (e.g., Sysmon EID 22) fail to record the activity.

To bridge this visibility gap, the analytic engine monitors both network traffic and process creation:

    Network IDS Monitoring (Suricata): Monitors virtual and physical interfaces via eve.json. It flags traffic matching known infrastructure domains (lab.local) or high-frequency network flows on port 53.

    Process Tracking (Sysmon EventID 1): Captures binary execution events on the endpoint (Image, CommandLine).

    Multi-Source Filtering: Applying the filter where mvcount(sources)>1 reduces baseline volume by requiring concurrent evidence from different telemetry layers within the same time window, filtering out isolated local network events.

# A. Writing the Splunk Query

- [Splunk SPL](../Rules/Splunk-SPL/Command-and-Control/dns-tunneling-correlation.spl) 👈

# B. Testing the Rule
To simulate the channel, an iodine server is deployed on an external gateway (Kali Linux at 192.168.56.102), acting as the authoritative name server for lab.local. On the target Windows host, the execution utility is initiated using the command .\iodine.exe.exe -f -r 192.168.56.102 lab.local against the VirtualBox Host-Only interface (192.168.56.1). ICMP traffic (ping) is then generated inside the tunnel to simulate network activity.

# C. Log Verification in Splunk 
When the baseline criteria intersect within the 10-minute time window, the SIEM platform aggregates the telemetry layers into the structured table layout:

    Sources & Telemetry Overlap: The sources array records the convergence of Suricata-Alert, Suricata-Flow, Suricata-DNS, and Sysmon-Process. The multi-source filter significantly reduces benign noise by requiring concurrent host and network evidence, though further tuning is required to eliminate residual cross-traffic (such as external resolver IP 114.114.114.114 or local multicast strings) captured within the shared time windows.

    CommandLine Audit Trail: Captures the actual execution string: .\iodine.exe.exe -f -r 192.168.56.102 lab.local. This provides process-level context regarding the destination C2 IP and the targeted domain configuration.

    Alert Signature: The alert column populates with the custom IDS rule signature: SUSPICIOUS DNS Tunneling Activity - iodine (lab.local), verifying that the Suricata engine parsed and flagged the target domain pattern.

    Network Volumetrics & Protocol Audit: The analytic successfully extracts nested JSON metadata from Suricata's DNS arrays using the spath command (dns.queries{}.rrtype). The output maps the exact query types utilized during the attack, explicitly isolating high volumes of NULL records combined with asymmetric bytes_out metrics. This provides forensic proof of raw-socket data encapsulation directly on the dashboard.

    Host Mapping: The correlation aligns the network endpoints (192.168.56.1 and 192.168.56.102) with the specific host asset DESKTOP-MJ170VE, providing the exact endpoints needed for standard containment procedures.


![Splunk Search](../screenshots/dns-tunneling-correlation-1.png?v=2)
