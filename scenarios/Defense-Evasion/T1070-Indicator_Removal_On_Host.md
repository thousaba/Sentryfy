# TECHNIQUE: INDICATOR REMOVAL ON HOST (T1070)
# Sub-Technique: Indicator Removal on Host: Clear Windows Event Logs (T1070.001)

One of the most common techniques attackers use is clearing logs to avoid leaving traces. We therefore need to detect this action as well.

# A. Writing the Splunk Query

- [Splunk SPL](../../Rules/Splunk-SPL/Defense-Evasion/event-log-clearing.spl) 👈


# B. Log Verification in Splunk

![Splunk Search](../../screenshots/splunk-event-log-1.png?v=2)
