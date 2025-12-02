import pandas as pd
import datetime
import sys
import os
from fpdf import FPDF

# This block has each specific rule alert names to a detailed explanation, why it's dangerous, and an action to take
# Takes the raw alerts in the provided log and makes them human-readable
KNOWLEDGE_BASE = {
    "WEB-ATTACK Directory Traversal Attempt": {
        "description": "An attempt was detected to access files outside the web root folder (e.g., using '../').",
        "danger": "CRITICAL. If successful, this allows attackers to read sensitive system files (like /etc/passwd) or configuration data.",
        "rank": 1, # Rank 1 means it is the highest priority 
        "action": "Immediate: Block Source IP. Check web logs to see if a 200 OK response was returned."
    },
    "TELNET connection attempt": {
        "description": "Unencrypted remote command-line connection attempt detected (Port 23).",
        "danger": "HIGH. Telnet sends everything (including root passwords) in cleartext. Attackers can easily sniff credentials.",
        "rank": 2,
        "action": "Disable Telnet services immediately. Enforce SSH usage."
    },
    "FTP connection attempt": {
        "description": "File Transfer Protocol connection attempt detected (Port 21).",
        "danger": "MEDIUM. FTP transmits data and credentials in cleartext. Vulnerable to Man-in-the-Middle attacks.",
        "rank": 3,
        "action": "Verify if transfer is authorized. Switch to SFTP or FTPS."
    },
    "POLICY VIOLATION: Facebook Access": {
        "description": "Traffic detected destined for social media (Facebook) domains.",
        "danger": "LOW (Policy). Risks include productivity loss, tracking, and potential malware distribution vectors.",
        "rank": 4,
        "action": "Review corporate usage policy. Scan source host for unauthorized browser extensions."
    },
    "ICMP Ping": {
        "description": "ICMP Echo Request (Ping) packet detected.",
        "danger": "INFO/LOW. Standard connectivity test, but can be used by attackers to map the network (Reconnaissance).",
        "rank": 5, # Rank 5 means it is the lowest priority
        "action": "Monitor for high-volume scanning patterns. Ignore if part of standard maintenance."
    }
}

# If there is an alert that is not in the pre-defined rule-set, this is the fallback 
DEFAULT_INFO = {
    "description": "General network alert detected by Suricata.",
    "danger": "Unknown. Requires manual investigation.",
    "rank": 99, # 99 meqaning low prioirty and automatically pushes the alert to the bottom of the report
    "action": "Investigate raw logs."
}

def get_input_file():
    """
    Asks the user for the input CSV filename.
    If the file does not exist or quotes were included in the path, it repormpts the user.
    """
    while True:
        filename = input("\nEnter the name of your CSV file (e.g., Report.csv): ").strip()
        
        # Remove quotes if the user dragged and dropped the file because doing so adds quotes
        filename = filename.replace("'", "").replace('"', "")
        
        # If a file is found, then continues, if not, the user is prompted with an error and is requested to try again
        if os.path.isfile(filename):
            print(f"[OK] Found file: {filename}")
            return filename
        else:
            print(f"[ERROR] Could not find '{filename}'. Please check the name and try again.")
            print("Tip: You can drag and drop the file into this terminal to get the full path.")

def load_and_enrich_data(filepath):
    """
    Reads the input CSV file, translates the Unix timestamps to human-readable ones, and adds the pre-defined alert explanations
    """
    try:
        df = pd.read_csv(filepath)
    except Exception as e:
        print(f"Error reading CSV file: {e}")
        sys.exit(1)

    # Convert Unix Timestamp to a Readable Date
    df['_time'] = pd.to_numeric(df['Time'], errors='coerce')
    df['Readable_Time'] = df['_time'].apply(
        lambda x: datetime.datetime.fromtimestamp(x).strftime('%Y-%m-%d %H:%M:%S') if pd.notnull(x) else "Unknown"
    )

    # Add the pre-defined alert explanations by checking each row's 'Alert Name' against the pre-defined alerts
    # Then fills in new columns with the description, why it's dangerous, the rank, and actions to take
    def get_enrichment(alert_name, field):
        # Partial matching if the alert does not fully match even if the log has extra text
        for key in KNOWLEDGE_BASE:
            if key in str(alert_name):
                return KNOWLEDGE_BASE[key].get(field)
        return DEFAULT_INFO[field]

    # Apply's the previous function that adds the pre-defined data to create new columns
    df['Description'] = df['Alert Name'].apply(lambda x: get_enrichment(x, 'description'))
    df['Danger_Analysis'] = df['Alert Name'].apply(lambda x: get_enrichment(x, 'danger'))
    df['Severity_Rank'] = df['Alert Name'].apply(lambda x: get_enrichment(x, 'rank'))
    df['Recommended_Action'] = df['Alert Name'].apply(lambda x: get_enrichment(x, 'action'))

    # Sort by Severity (Rank 1 is highest priority) and sorts the time from the newest first
    df_sorted = df.sort_values(by=['Severity_Rank', 'Readable_Time'], ascending=[True, False])
    
    return df_sorted

def generate_csv_report(df):
    """
    Exports the data to a CSV file
    """
    output_name = "Detailed_Security_Report.csv"
    # Defines the column order for the output
    cols = ['Readable_Time', 'Severity_Rank', 'Alert Name', 'Source IP', 'Destination IP', 'Description', 'Danger_Analysis', 'Recommended_Action']
    df[cols].to_csv(output_name, index=False)
    print(f"\n[SUCCESS] CSV Report generated: {output_name}")

def generate_pdf_report(df):
    """
    Inserts more visuals in the PDF report
    """
    output_name = "Detailed_Security_Report.pdf"
    pdf = FPDF()
    pdf.ws = 0 
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()
    
    # Title
    pdf.set_font("Arial", "B", 16)
    pdf.cell(0, 10, "Suricata Network Security Incident Report", ln=True, align='C')
    
    # Timestamp section
    pdf.set_font("Arial", "I", 10)
    current_time = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    pdf.cell(0, 10, f"Generated on: {current_time}", ln=True, align='C')
    pdf.ln(10) # Adds a line break

    # Loop through events and print it to the PDF
    for index, row in df.iterrows():
        # Header Color based on Rank
        rank = row['Severity_Rank']
        if rank == 1:
            pdf.set_text_color(200, 0, 0) # Red for Critical
        elif rank <= 3:
            pdf.set_text_color(200, 100, 0) # Orange for Medium
        else:
            pdf.set_text_color(0, 0, 0) # Black for Low

        # Print the alert title
        pdf.set_font("Arial", "B", 12)
        alert_title = f"[{str(row['Readable_Time'])}] {str(row['Alert Name'])}"
        pdf.cell(0, 8, alert_title, ln=True)
        
        # Reset color to black for details
        pdf.set_text_color(0, 0, 0)
        pdf.set_font("Arial", "", 10)
        
        # Prints the Details Block
        src_dest = f"Source: {str(row['Source IP'])}  -->  Destination: {str(row['Destination IP'])}"
        analysis = f"Analysis: {str(row['Description'])}"
        danger = f"Why it is Dangerous: {str(row['Danger_Analysis'])}"
        action = f"Recommended Action: {str(row['Recommended_Action'])}"

        pdf.multi_cell(0, 6, src_dest)
        pdf.multi_cell(0, 6, analysis)
        
        # Changes font to Italic for the Danger section
        pdf.set_font("Arial", "I", 10)
        pdf.multi_cell(0, 6, danger)
        
        # Changes font to Bold for the Action section
        pdf.set_font("Arial", "B", 10)
        pdf.multi_cell(0, 6, action)
        
        pdf.ln(3)
        # Inserts a line separator between events
        pdf.line(10, pdf.get_y(), 200, pdf.get_y()) 
        pdf.ln(5)

    pdf.output(output_name)
    print(f"\n[SUCCESS] PDF Report generated: {output_name}")

def main():
    print("--- Splunk/Suricata Alert Report Generator ---")
    
    # Ask user for file 
    input_file = get_input_file()
    
    # Load data
    df = load_and_enrich_data(input_file)
    
    # Prints summary stats back to the terminal
    total_alerts = len(df)
    critical_alerts = len(df[df['Severity_Rank'] == 1])
    
    print(f"\nAnalysis Complete.")
    print(f"Total Alerts Found: {total_alerts}")
    print(f"CRITICAL Alerts: {critical_alerts}")
    
    # Ask the user for the output file
    while True:
        choice = input("\nWould you like to export to CSV or PDF? (Enter 'csv' or 'pdf'): ").strip().lower()
        if choice == 'csv':
            generate_csv_report(df)
            break
        elif choice == 'pdf':
            generate_pdf_report(df)
            break
        else:
            print("Invalid choice. Please enter 'csv' or 'pdf'.")

if __name__ == "__main__":
    main()
