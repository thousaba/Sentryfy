# HARDWARE ADDITIONS (T1200) USB-Originating Threat Detection (Risk-Based Scoring)

Since correlation rules are not compatible with Sigma format, we will implement this type of rule directly as a Splunk query.

This rule is designed to detect suspicious processes triggered shortly after a USB device is connected to the system, and to analyze the threat level of these processes using Risk-Based Alerting (RBA).

---
# A. Writing the Splunk Query

- [Splunk SPL](../../Rules/Splunk-SPL/Initial-Access/usb-threat-detection.spl) 👈 


Rather than a static detection, the rule establishes a dynamic correlation between two distinct events:

    1- USB Connection Detection (Event Code 6416): Triggered when a new device is connected. Known and trusted devices (Whitelist) are filtered by DeviceId.
    2- Process Creation (Event Code 4688): All processes started within 30 seconds of the USB connection are monitored.

---
The query evaluates each suspicious activity it captures with a "Risk Score." The higher the score, the greater the alert severity:

    Process Identity (+5 Points): A base score is assigned if attacker-favored tools (LOLBins) such as powershell.exe, cmd.exe, rundll32.exe, or mshta.exe are detected.

    Command Line Analysis (+1 to +3 Points):
        Encoded command usage (-enc, EncodedCommand).
        Attempts to download files from the internet (DownloadString, WebClient).
        Hidden window or privilege bypass (-WindowStyle Hidden, -ExecutionPolicy Bypass).

    Parent-Child Process Analysis (+2 to +4 Points): If the process is spawned by system services such as services.exe or lsass.exe instead of explorer.exe (normal user), it is scored as "critical" risk.

    Time Bonus (+2 to +3 Points): Processes starting within the first 5 seconds after a USB connection are given extra points as a direct indicator of a hardware attack (BadUSB/Rubber Ducky).

---
# B. False Positive Management

To avoid overwhelming SOC operations, the following scenarios are automatically excluded or have their score reduced:

    PnP Driver Installations: Legitimate driver processes started by Windows for the connected device (streamci, shell32.dll calls, etc.) are filtered out.
    Legitimate Software: Routine checks triggered by Splunk's own Python services are suppressed to reduce noise.

---
# C. Log Verification in Splunk

![Splunk Search](../../screenshots/splunk-usb-4.png?v=2)

---


# HARDWARE ADDITIONS (T1200) USB HID (KEYBOARD) DETECTION — BADUSB 

"This rule is designed to detect Rubber Ducky/BadUSB attacks (MITRE T1200) that exploit the operating system's blind trust in peripherals by emulating HID (Human Interface Device) behavior."

A normal user does not plug in a new keyboard every day at work. If a new device suddenly appears in the HIDClass or Keyboard class on a machine, there are two possibilities:

  1- The user's keyboard broke and they plugged in a new one. (False Positive)
  2- Someone plugged that sneaky Rubber Ducky into the machine and is currently injecting commands into your PowerShell at 1000 words per second. (Critical Attack)

# A. Writing the Splunk Query

One important thing to keep in mind when writing this rule is to whitelist our own mouse and keyboard devices. Otherwise, we will be flooded with false positive alerts.

- [Splunk SPL](../../Rules/Splunk-SPL/Initial-Access/usb-hid-detection.spl) 👈


# B. Log Verification in Splunk

![Splunk Search](../../screenshots/splunk-usb-5.png?v=2)
