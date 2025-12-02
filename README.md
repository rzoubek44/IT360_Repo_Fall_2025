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
- Add the full path of the new file to suricata.yaml file 
- Adding ICMP ping rule to alert if a device sends a ping request to you (alert icmp any any -> $HOME_NET any (msg:”ICMP Ping”; sid:1; rev:1;))
- This will generate an alert for an ICMP protocol from any IP address and port to your device’s IP address from any port.
- Test with: ping 192.168.1.184 (target IP address) from another device in the network and view the fast.log to see the new alert (e.g. 11/25/2025-15:30:32.226145  [**] [1:1:1] ICMP Ping [**] [Classification: (null)] [Priority: 3] {ICMP} 192.168.1.181:8 -> 192.168.1.184:0)
- Adding a telnet rule to alert if the device tries to make a telnet connection to another device (alert tcp any any -> any 23 (msg:"TELNET connection attempt"; sid:1000001; rev:1;))
- This will alert when there is a tcp connection from any IP address and any port to any IP address to port 23 (Telnet)
- Test with: telnet 192.168.1.181 (target IP address) to another device and view the fast.log to see the new alert (e.g. 11/25/2025-15:59:59.648754  [**] [1:1000001:1] TELNET connection attempt [**] [Classification: (null)] [Priority: 3] {TCP} 192.168.1.184:37882 -> 192.168.1.181:23)
- Adding a FTP rule to alert if the device tries to make a FTP connection to another device (alert tcp any any -> any 21 (msg:"FTP connection attempt"; sid:1000004; rev:1;))
- This will alert when there is a tcp connection from any IP address and any port to any IP address to port 21 (FTP)
- Test with: ftp 192.168.1.181 (target IP address) to another device and view the fast.log to see the new alert (e.g. 11/26/2025-11:42:30.503167  [**] [1:1000004:1] FTP connection attempt [**] [Classification: (null)] [Priority: 3] {TCP} 192.168.1.184:38032 -> 192.168.1.181:21)
- Adding a Web Application Directory Traversal alert if the device queries a directory traversal on a website link (alert http any any -> any 80 (msg:"WEB-ATTACK Directory Traversal Attempt"; content:"../"; http_raw_uri; classtype:web-application-attack; zsid:1000005; rev:2;))
- This will alert when there is an attempt to directory traversal on a website link on port 80 from any IP and port to any IP and port 80 (HTTP)
- Test with: Test: curl -v --path-as-is "http://testmynids.org/../../etc/passwd" on the device and view the fast.log to see the new alert (e.g. 11/26/2025-16:20:19.952386  [**] [1:1000005:2] WEB-ATTACK Directory Traversal Attempt [**] [Classification: Web Application Attack] [Priority: 1] {TCP} 192.168.1.184:50184 -> 3.170.103.11:80)
- Adding a DNS rule to alert if the device tries to visit facebook (alert dns any any -> any any (msg:"POLICY VIOLATION: Facebook Access"; dns.query; content:"facebook.com"; sid:1000006; rev:1;))
- This will alert when someone tries to connect to facebook. It can be used as a social media policy to see who is going on social media sites. You can set it to any of them like tik tok or instagram.
- Test with: nslookup facebook.com on the device and view the fast.log to see the new alert (e.g. 11/26/2025-11:55:24.061918  [**] [1:1000006:1] POLICY VIOLATION: Facebook Access [**] [Classification: (null)] [Priority: 3] {UDP} 192.168.1.184:59897 -> 192.168.1.254:53)

Here is a link for documentation page for writing custom rule sets for Suricata: https://docs.suricata.io/en/latest/rules/intro.html

Installation and configuration of Splunk:
- Go to the Splunk website and create an account for the free trial 60 day version for Splunk enterprise
- Go to the Linux tab and download the .deb file (Debian/Ubuntu package)
- Go to the Downloads folder in the terminal and use the ls command to check for the filename and version (e.g. splunk-10.0.2-e2d18b4767e9-linux-amd64.deb)
- Install the package: sudo dpkg -i splunk-10.0.2-e2d18b4767e9-linux-amd64.deb
- Start splunk and accept the license: sudo /opt/splunk/bin/splunk start --accept-license
- Create admin account
- The terminal will ask you to create a username and password for the admin account
- Follow the prompts to enter username and password
- After that, open the link at the end of the output for the splunk web interface (http://kali:8000 or http://localhost:8000)
- Enter credentials for the admin account to get into the home page

Pointing the log file from Suricata to Splunk:
- On the Splunk web browser, go to the top bar and click “Settings”, then “Data inputs”
- Add a new input by clicking on “files and directories” under “local inputs”
- Click on “new local file and directory”
- In the “file or directory” field, hit “browse” to enter the path of the suricata log file (/var/log/suricata/eve.json, Make sure “continuously monitor” option is selected)
- In “set source type”, click on the drop down menu “source type” and type “json” (Select _json which will work for our eve.json files)
- In “Input settings” for the “index” drop down menu, select main (In the “host method”, select “constant value”) (In the “Host Field”, enter a name like kali-vm because this will tag every event and you know exactly which machine sent it)
- Click “review”, “submit”, “Start Searching”

Using Splunk:
- Click on the “app” dropdown menu and select “Search and reporting” app
- In the search bar, enter this command: index="main" sourcetype="_json" to verify data is flowing
- To the right of the search bar, change “Last 24 hours” to “Real-time” > “30 second window’
- This will test for data right now and get to watch attacks happen live
- Then click the green magnifying glass
- If there is nothing, start the suricata service: sudo systemctl start suricata
- Then generate traffic: curl http://testmynids.org/uid/index.html
- Then there will be alerts popping up
- Once the search runs, look at the left sidebar labeled “interesting fields”
- Since we used “sourcetype=”_json”, Splunk automatically scans the suricata log and pulled out the keys
- Scroll down on the side bar and look for fields like “src_ip”, “dest_ip”, or “alert.signature or alert.signature_id”

Splunk Reporting:
- Once data flow in confirmed, put this SPL script into the search bar and click the magnifying glass again

(index="main" sourcetype="_json" event_type="alert"
| table _time, src_ip, dest_ip, alert.signature, alert.category, alert.severity
| rename _time as "Time", src_ip as "Source IP", dest_ip as "Destination IP", alert.signature as "Alert Name", alert.category as "Category", alert.severity as "Severity"
| sort - "Time")

- Start the suricata service again, run the same curl command to generate traffic that will set off an alert, then stop suricata
- Once the table looks how you want it, click on “save as”, select “report” from dropdown, give it a title name and an optional description, then click “save”
- This is now a permanent report that saves the script
- Now you can review the report by going to the “reports” tab on the top bar, find the newly generated report and click on it, click on it to run the script and this will generate a table automatically of alerts
- To export and view the report as a table in PDF or CSV, click on the export button

Get a report on the custom rules:
- To view the custom rules and alerts, start the suricata service and run these commands
- ping 192.168.1.184 (target IP address)
- telnet 192.168.1.181 (target IP address)
- ftp 192.168.1.181 (target IP address)
- nslookup facebook.com
- curl -v --path-as-is "http://testmynids.org/../../etc/passwd"
- View the fast.log file to confirm all these events where alerted
- Start up splunk and go to "Search and Reporting" app
- Add the SPL script from above
- Change “Last 24 hours” to “Last 15 minutes"
- This will look at the log file for new alerts in the last 15 minutes
- Click the magnifying glass to see the table view of the alerts
- Export to view the report as a CSV file so it is ready to be ran by the script

Report Script:
- Get the script from the src document names, "Security_Report_Generation.py"
- Install fpdf and pandas package: pip install pandas fpdf --break-system-packages
- Make the script executable: chmod +x Security_Report_Generation.py
- Run the script: python3 Security_Report_Generation.py (make sure the Splunk generated report is in the same directory as the script)
- Must enter a .csv file as input, so save the report as a CSV on Splunk
- Choose either a .csv file or .pdf file as output
- Will get a detailed report as output, ranking the alerts and provides details and remediation recommendations 
