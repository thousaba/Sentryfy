# REPLICATION THROUGH REMOVABLE MEDIA (T1091) : UNAUTHORIZED USB DEVICE CONNECTED

We write a rule to generate alerts when unknown USB devices are connected to the system.

# A. Writing the Rule with Sigma

Click the link to access the rule file.
- [Sigma Rule (YML Format)](../../Rules/Sigma/unauthorize_usb.yml) 👈 


# B. Testing the Rule

We connect a USB device that is not on the whitelist in the rule to our computer.

# C. Log Verification in Splunk

As seen, Windows printer drivers and audio devices also belong to the "Plug and Play" mechanism, so their logs started appearing as false positives. However, our goal is only to detect physically connected external USB devices.

![splunk search results](../../screenshots/splunk-usb-1.png?v=2)

For this reason, we add the following filter to our rule:

```
filter_noise:
    win.eventdata.className:
      - 'PrintQueue'          # Virtual printer queues
      - 'SoftwareDevice'      # Software virtual devices
      - 'AudioEndpoint'       # Audio device plug/unplug noise
    win.eventdata.deviceDescription|contains:
      - 'Microsoft Print to PDF'
      - 'Root Print Queue'
      - 'Generic software device'
```

As shown below, we have successfully suppressed the false positive logs.

- [Sigma Rule (YML Format)](../../Rules/Sigma/brute-force.yml) 👈 

