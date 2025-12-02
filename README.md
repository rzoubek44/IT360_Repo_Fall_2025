# IT360_Repo_Fall_2025
Link to demo video: https://youtu.be/MBO27umAYgE

This will be a project of using Splunk and Suricata to generate an alert file that is directly ingested by Splunk to populate the alerts into a basic report. Then a python script is ran to get a more detailed report to view the alerts in more detail. 

Customs rules are written inside the local.rules file in the rule direcotry of Suricata. You can write any custom rules based on your needs and decide what to do with the packet once it is detected. It acts like an Intrusion Detection and Prevention System. For the purpose of this project, we wrote custom rules to only generate alerts. Then generating network traffic so alerts populate the log file for Splunk to read.

Once the log file is populated with alerts, configure Splunk to point to the log file. Then running the search function in alert and reporting applcation will print out all the alerts with important information like IP addresses, signatures, and timestamps. Inputting the SPL script in the search bar will organize the alerts in a table. 

Export the table into a CSV file and running the script will generate a detailed report of all the alerts in the file. It ranks the severity of each alert, provides a description of the alert, why it's dangerous, and actions to be taken to remediate/fix it. This is very useful for analysts because the report is human-readable and provides useful information for them to take actions against them. 

This project utulizes two tools and a script to track suspicious nertwork traffic and generate a detailed report to automate the process.

# List of Features

# Instructions
