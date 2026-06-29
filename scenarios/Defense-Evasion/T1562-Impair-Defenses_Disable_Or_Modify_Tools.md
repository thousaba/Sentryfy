# IMPAIR DEFENSES: DISABLE OR MODIFY TOOLS (T1562)
# Sub-Technique: Disable or Modify Tools (T1562.001)

This rule detects unauthorized modifications to the Windows Registry aimed at disabling LSA (Local Security Authority) Protection.

It monitors Registry EventID 13 (Value Set) specifically targeting the RunAsPPL registry key. When this value is set to 0, it effectively disables the Protected Process Light (PPL) mechanism for LSASS, allowing attackers to perform credential dumping from memory using tools like Mimikatz or PPLDump.

This matters because LSA Protection is a critical defense-in-depth feature. Disabling it is a clear indicator of Impair Defenses (T1562), usually occurring right before an attacker attempts to harvest clear-text passwords or NTLM hashes to move laterally across the network.

# A. Writing the Splunk Query

- [Splunk SPL](../../Rules/Splunk-SPL/Defense-Evasion/ppl-disabled.spl) 👈


# B. Testing the Rule

To simulate this defense evasion technique, we manually modify the registry to disable LSA protection. This requires administrative privileges and will trigger a Registry Object Value Set event.

![Testing Rule](../../screenshots/ppl-disabled-2.png?v=2)

# C. Log Verification in Splunk

Once the registry key is modified, Splunk will capture the event. The Details field will show DWORD (0x00000000), and our query will flag the action as PPL_DISABLED. This should be treated as a high-severity alert, as it directly precedes credential theft.

![Splunk Search](../../screenshots/ppl-disabled-1.png?v=2)

