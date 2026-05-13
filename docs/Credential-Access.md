### 1- BRUTE FORCE (T1110) 

# A. Writing a Brute Force Rule with Sigma

We write the Brute Force detection rule — already created in the Rules folder — in Sigma format. We then convert this rule to Splunk format. Sigma automatically generates a Splunk query for us. We will later use this query in the Splunk system for log detection and alert generation.

Click the link to access the rule file.
- [Sigma Rule (YML Format)](../Rules/Sigma/brute-force.yml) 👈 

# B. Simulating a Brute Force Attack with PowerShell for Testing

We run PowerShell as administrator. We then simulate a fake brute force attack with the command below, targeting Splunk which monitors Windows logs.

![splunk alert config](../screenshots/splunk-bruteforce-2.png?v=2)

# C. Log Verification in Splunk

It's time to use the converted Splunk query. We paste the converted query into the Search Bar in Splunk's Search & Reporting section. The test confirms that the brute force log has been ingested into Splunk. We can capture this log either as an alert or as a chart on a Dashboard we create inside Splunk.

![backend webhook code](../screenshots/splunk-bruteforce-1.png?v=2)

# D. Splunk Dashboard 
We can track the brute force attack performed against the user "HackerTurkoglu" on the Dashboard we created in Splunk using a Pie Chart. This chart lets us monitor the number of attacks against each user.

![sigma rule](../screenshots/splunk-bruteforce-3.png?v=2)



# E. Telegram Notification

Instant notifications arriving through the bot we configured with Express in the Telegram application.

![splunk search results](../screenshots/splunk-bruteforce-4.png?v=2)
