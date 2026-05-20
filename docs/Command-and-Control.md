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
