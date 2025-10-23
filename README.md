# Automated Log Analysis and Alerting System  
**Course:** CYB-333 – Security Automation  
**Student:** Andrew Hembree  

---

## 📘 Project Overview

This project was created as part of my CYB-333 Security Automation course. My goal was to build a practical Python tool that could automatically scan and analyze log files to detect signs of suspicious or abnormal system activity.  

The program looks for failed login attempts, repeated error messages, and unauthorized web access attempts. It then generates clean, easy-to-read reports (in JSON and CSV formats) and can also send a daily email summary of any alerts it finds.  

I built this project to get hands-on experience with how automation can make security work more efficient, especially for analysts who deal with huge amounts of log data every day.

---

## 🎯 Objectives

- Automate log analysis using Python.  
- Detect security-related anomalies like failed logins or repeated error events.  
- Output clear and organized reports for review.  
- Automatically email a summary of alerts each day.  
- Enrich IP addresses with information like country, city, and organization.  
- Learn how scripting and automation can help real-world SOC operations.

---

## 🧰 Main Features

| Feature | Description |
|----------|-------------|
| **Automated Log Scanning** | Parses system or web logs line-by-line and looks for specific patterns. |
| **Regex-Based Detection** | Uses regular expressions to find failed logins, errors, and unauthorized web access. |
| **Sliding Time Window** | Detects bursts of repeated events within a set time window. |
| **Multi-Format Reporting** | Exports reports in both JSON and CSV formats. |
| **Email Notifications** | Sends summaries of detected alerts via SMTP (supports TLS/SSL). |
| **IP Enrichment** | Adds geolocation and ASN/organization info for attacker IPs. |
| **.env Configuration** | Securely stores email and API credentials outside of the main script. |

---

## 🧱 Project Structure

src/
	log_analyzer.py
data/
  sample_logs/
reports/        
# generated automatically

.env.example    

# environment variable template
requirements.txt
notebooks/      

---

## ⚙️ Technologies Used

- **Python 3.10+**  
- **Requests** (for IP enrichment APIs)  
- **python-dotenv** (for environment variables)  
- *(Optional)* **Pandas**, **Matplotlib**, and **Jupyter Notebook** for analysis and visualization  

---

## 💾 Dependencies

Your `requirements.txt` should include:
python-dotenv
requests
# Optional visualization libraries
# pandas
# matplotlib
# jupyter

Install dependencies:
pip install -r requirements.txt

---

## 🧩 How It Works

1. **Log Parsing**  
   The script reads log files line by line and searches for common signs of attacks or errors using regex patterns.

2. **Event Detection**  
   It groups similar events within a specific time window (for example, 5 minutes). If the number of events passes a set threshold, it triggers an alert.

3. **IP Enrichment**  
   The tool queries public APIs (like ipinfo or ipapi) to find out where attacker IPs originate from (city, country, and organization).

4. **Report Generation**  
   Alerts and related log events are saved as CSV and JSON files in the `reports/` folder.

5. **Email Alerts**  
   An automated summary email is sent to the configured address. Even if no alerts are found, a message is still sent to confirm that the scan completed.

---

## 🔧 Setup and Installation

1. **Clone or Download Repository**
   git clone https://github.com/DrHembree/log-alert-automation.git
   cd log-alert-automation

2. **Create and Activate a Virtual Environment**
   python3 -m venv .venv
   source .venv/bin/activate
   pip install -r requirements.txt

3. **Configure Environment Variables**
   Copy the example file and fill in your info:
   cp .env.example .env

   Example `.env`:
   SMTP_HOST=smtp.gmail.com
   SMTP_PORT=587
   SMTP_USER=you@example.com
   SMTP_PASS=your_app_password
   SMTP_FROM=Log Monitor <you@example.com>
   SMTP_TO=you@example.com
   SMTP_TLS=1
   SMTP_SSL=0
   IPINFO_TOKEN=

4. **Run the Analyzer**
   python src/log_analyzer.py      --log data/sample_logs/syslog_sample.log      --out reports      --format json csv      --rules failed_logins errors sudo_failures web_unauthorized      --window 300 --threshold 3

---

## 🧪 Example Output

Console Example:
[+] Wrote reports to base: reports/report_20251022_220056
[!] ALERTS:
  - failed_logins at 2025-10-14T12:01:10 (count=4)
  - errors at 2025-10-14T12:03:45 (count=3)

Email Example:
Alerts generated:

{
  "rule": "failed_logins",
  "start": "2025-10-14T12:01:10",
  "count": 4
}

Origins:
 - 198.51.100.33: US/Chicago (AS15169 Google LLC)

---

## 📊 Optional: Visualization Notebook

You can open the `notebooks/analysis.ipynb` file to visualize alert data using Pandas and Matplotlib.

jupyter notebook notebooks/analysis.ipynb

The notebook can show:
- Bar charts for alert counts by rule type  
- Tables of unique IPs and timestamps  

---

## 💡 Notes and Takeaways

Building this project helped me understand how automation fits into real-world cybersecurity. It taught me how log analysis, scripting, and APIs can all work together to improve security monitoring.  

The process also made me better at writing reusable code and handling errors gracefully (like missing logs, failed API calls, or bad email credentials).  

It’s simple enough for classroom use but structured like something you’d find in an entry-level SOC or blue team environment.

---

## 🧠 Code Documentation

All key functions include comments and docstrings that explain their purpose and inputs/outputs.

Example:
def detect_failed_logins(lines, window=300, threshold=5):
    """
    Detects repeated SSH failed login attempts within a time window.

    Args:
        lines (list): Log file lines.
        window (int): Time window in seconds.
        threshold (int): Event count to trigger an alert.
    Returns:
        tuple: (alerts list, events list)
    """

Style and Structure:
- Follows PEP8 style and consistent indentation.  
- Uses clear and meaningful variable names (like all_alerts, unique_ips, write_reports).  
- Includes error handling for SMTP, file access, and API requests.  
- Organized into logical functions for:
  - Parsing (detect_*)
  - Enrichment (enrich_ips)
  - Reporting (write_reports)
  - Email alerts (send_email_if_alerts)

-----------

## 🧹 Troubleshooting
No emails received
	-Use Gmail App Password and verify TLS/SSL settings 
No alerts detected 
	-Lower the threshold or expand the time window 
IP lookup failed
	-Check internet connection or API token
Reports not created 
	-Verify folder permissions (auto-created if missing)

-------------

## 🔒 Security Notes
- Do **not** share real logs publicly.  
- Never upload your `.env` file — only share `.env.example`.  
- Generated reports may include sensitive information. Treat them as confidential.

---

## 🧾 Conclusion

This project showed me how powerful security automation can be when it comes to simplifying repetitive analysis tasks. Writing this tool gave me a much better understanding of Python scripting, regex matching, and how to integrate APIs securely into cybersecurity workflows.  

If I expand this project in the future, I’d like to add a real-time dashboard and integrate it with a SIEM for continuous monitoring.

---
