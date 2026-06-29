# PHISHING (T1566) - SUSPICIOUS FILE CREATION FROM COMMUNICATION APPS
This rule detects the initial stage of a phishing attack by monitoring for suspicious file types (LNK, EXE, BAT, JS, etc.) being written to the disk by common communication or browser applications. This is a primary indicator of Initial Access, occurring when a user downloads a malicious attachment or is redirected to a drive-by download.

It monitors Sysmon EventID 11 (File Create). By filtering out legitimate system processes like explorer.exe or msiexec.exe, the rule highlights instances where applications like outlook.exe, chrome.exe, or teams.exe drop executable or script files into user-writable directories.

This matters because catching the file at the moment of creation—before it is ever executed—allows for proactive containment. If an analyst can identify a malicious .lnk or .vbs file being dropped by an email client, they can intervene before the user even has a chance to double-click and trigger the execution phase.

# A. Writing the Splunk Query

- [Phishing](../../Rules/Splunk-SPL/Initial-Access/phishing.spl) 👈

# B. Testing the Rule 

To simulate this initial access vector, we run a PowerShell script that creates a malicious shortcut (.LNK) file on the desktop, mimicking a common phishing technique.

```powershell
$shell = New-Object -ComObject WScript.Shell
$shortcut = $shell.CreateShortcut("$env:USERPROFILE\Desktop\2026_Maas_Zam_Listesi.lnk")
$shortcut.TargetPath = "powershell.exe"
$shortcut.Arguments = "-ExecutionPolicy Bypass -WindowStyle Hidden -Command Write-Host 'Phishing'"
$shortcut.Save()
```

# C. Log Verification in Splunk

The Splunk dashboard captures the Event ID 11 immediately. In the results, we can see the exact process that created the file (e.g., powershell.exe in our test, or outlook.exe in a real attack) and the full path to the dropped artifact. This provides immediate forensic evidence of how the threat entered the environment.

![Splunk Search](../../screenshots/phishing-1.png?v=2)
