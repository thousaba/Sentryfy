# ACCOUNT MANIPULATION (T1098)

In this attack type, the attacker modifies existing user accounts on the system or establishes persistence through newly created accounts.

# A. Writing the Splunk Query

Noise Suppression: Excluding service accounts with `$$` and standard users like SYSTEM is critical. This is where we silence the vast majority of false positives.

Group Filter: We use `where` to exclude insignificant groups such as Users or None, preventing alert fatigue.

- [Splunk SPL](../../Rules/Splunk-SPL/Persistence/account-manipulation.spl) 👈

# B. Testing the Rule
Figure 1.1: Executing Atomic Red Team T1098.001 (Admin Account Manipulate)

    Description: Simulating an adversary behavior using Atomic Red Team framework to manipulate privileged accounts.

    Execution: The test triggers a defense evasion technique by automatically renaming the built-in local Administrator account to a randomized string (HaHa_594854421438). This mimics real-world attacks aimed at bypassing basic, keyword-based detection mechanisms.

![Splunk Search](../../screenshots/splunk-account-1.png?v=2)

# C. Log Verification in Splunk
Figure 1.2: Splunk Search Results and Detection Verification

    Description: Verification of the detection rule inside Splunk after the attack simulation.

    Key Highlights: * Telemetry Capture: The rule successfully captures the account modification behavior under Windows Security EventCode 4738 (User account modified / renamed).

        Evasion Defeated: Despite the attacker randomizing the username to evade detection, the SPL query successfully tracks the asset using its persistent Security Identifier (TargetSid matching -500 or Administrator).

        Alert Generation: The engine properly calculates risk metrics, automatically categorizing the event as High severity and triggering the specific alert type: Account Manipulation / Rename (T1098).

![Splunk Search](../../screenshots/splunk-account-2.png?v=2)
