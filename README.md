# IT360_Repo_Fall_2025
Link to demo video: https://youtu.be/MBO27umAYgE

This will be a project of using Splunk and Suricata to generate an alert file that is directly ingested by Splunk to populate the alerts into a basic report. Then a python script is ran to get a more detailed report to view the alerts in more detail. 

Customs rules are written inside the local.rules file in the rule direcotry of Suricata. You can write any custom rules based on your needs and decide what to do with the packet once it is detected. It acts like an Intrusion Detection and Prevention System. For the purpose of this project, we wrote custom rules to only generate alerts. Then generating network traffic so alerts populate the log file for Splunk to read.

Once the log file is populated with alerts, configure Splunk to point to the log file. Then running the search function in alert and reporting applcation will print out all the alerts with important information like IP addresses, signatures, and timestamps. Inputting the SPL script in the search bar will organize the alerts in a table. 

Export the table into a CSV file and running the script will generate a detailed report of all the alerts in the file. It ranks the severity of each alert, provides a description of the alert, why it's dangerous, and actions to be taken to remediate/fix it. This is very useful for analysts because the report is human-readable and provides useful information for them to take actions against them. 

This project utulizes two tools and a script to track suspicious nertwork traffic and generate a detailed report to automate the process.

# List of Features
This project involved Suricata, Splunk, and Python automation. Below is a lsit of features for the project. This breakdown shows the specific capabilities of each component in our "Mini-SOC" architecture.

Suricata Features:
- Real time monitoring of packet inspection from a network interface
- Utilizes the Emerging Threats Open ruleset to identify attack patterns
- The ability to create custom rules to detect specific threats based on your needs (Layer 4 and 7 detection for this project)
- Configured the EVE (Extensible Event Format) output to generate a log file for a machine to read, eve.json, for Splunk to ingest
- Convert the eve.json file from machine-readable to JSON format for human-readable

Splunk Features:
- Configured to automatically ingest the eve.json log in real time
- Extracts the log data into searchable fields (src_ip, dest_ip, alert.signature, alert.severity)
- Custom reporting by only filtering for security alerts (event_type="alert")
- Generate a custom SPL script to generate a structured table to view sorted fields
- Export the findings to provide a snapshot of all alerts to a CSV file for further analysis

Python Script Features:
- Reads the CSV export file from Splunk
- Maps the alert names from a pre-defined rule set
- Adds descriptive information for each alert (Description, Danger Analysis, and Recommendations)
- Sorts the report by the severity of the alert (Higher severity goes towards the top)
- User can choose between a CSV or PDF output file for the report
- Translates Unix time to human-readable time
- Color codes the alerts based on threat level (Red for critical, Black for Low)

# Instructions
To set up the project, you need to install and figure Suricata and Splunk. Also, download and run the python script with the CSV file as input to generate the report.

Installation of Suricata:
- First update the Kali VM: sudo apt update
- Install Suricata: sudo apt install suricata -y

Configure Suricata:
- Open the suricata.yaml file with your choice of text editor: sudo nano /etc/suricata/suricata.yaml
- Under address-groups, add your IP address subnet and CIDR number to HOME_NET (e.g. HOME_NET: “[10.0.2.0/24]”)
- Search for af-packet and change the interface to your network interface (e.g. Interface: eth0)
- Search for pcap and change that interface to your network interface (e.g. Interface: eth0)
- Search for community-id and change false to true (e.g. Community-id: true)
- Search for the output section and make sure eve-log is enabled. This ensures logs go to /var/log/suricata/eve.json which is the file extension that Splunk needs (e.g. Enabled: yes)
- Update the rules which downloads the latest emerging threats open ruleset and saves them to var/lib/suricata/rules/suricata.rules (sudo suricata-update)
- Check to see if the rules loaded: Sudo suricata -T -c /etc/suricata/suricata.yaml -v. It should say there were a number of rules successfully loaded
- All the IDS alerts will go to fast.log and it will go to eve.json in JSON format

Test Suricata:
- Start the service in the background (sudo systemctl start suricata)
- Check the status to make sure its active and running (sudo systemctl status suricata)
- You should see "Active: active (running)". If it says "failed," it's usually because the interface name was wrong
  
- Open a second terminal window, tail the log in real time to see new alerts (Tail -f /var/log/suricata/eve.json)
- In the first terminal, test the rule set with a command that will trigger a rule (curl http://testmynids.org/uid/index.html)
- This is checking for an ID and will see a JSON log entry appear in the second terminal window
- Cancel the command in the second terminal and view the fast.log file for the new alert (sudo cat /var/log/suricata/fast.log)
- There should be one entry for the new alert (e.g. 11/18/2025-21:59:12.036175  [**] [1:2100498:7] GPL ATTACK_RESPONSE id check returned root [**] [Classification: Potentially Bad Traffic] [Priority: 2] {TCP} 3.170.103.6:80 -> 10.0.2.15:38770)
- To view the JSON file in JSON format, install jq (Install jq: sudo apt install jq -y)
- Run this command in the first window: sudo tail -f /var/log/suricata/eve.json | jq 'select(.event_type=="alert")'
- In the second window, run the same command to trigger the alert: curl http://testmynids.org/uid/index.html
- The output in the first terminal will show the alert in readable JSON format (Make sure suricata is running to see the alert)

Writing Custom Suricata Rules:
- Make a file in the /etc/suricata/rules directory and name the file whatever you want (sudo nano /etc/suricata/rules/local.rules)
- Adding ICMP ping rule to alert if a device sends a ping request to you (alert icmp any any -> $HOME_NET any (msg:”ICMP Ping”; sid:1; rev:1;))
- This will generate an alert for an ICMP protocol from any IP address and port to your device’s IP address from any port.

- 
