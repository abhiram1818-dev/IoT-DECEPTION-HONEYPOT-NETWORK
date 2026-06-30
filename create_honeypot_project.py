#!/usr/bin/env python3
"""
Create complete project structure for IoT Honeypot (Project 2)
Run: python3 create_honeypot_project.py
"""

import os
import stat

# --------------------------------------------------------------------
# Project root folder
PROJECT_DIR = os.path.expanduser("~/honeypot_project")
# --------------------------------------------------------------------

# All file contents as (relative_path, content, is_executable)
FILES = [
    # Root files
    (".gitignore", """
logs/
data/
*.log
*.json
.env
__pycache__/
*.pyc
"""),

    ("README.md", """
# IoT Deception Honeypot Network

## Project Overview
This project deploys a Cowrie honeypot that mimics a medical IoT device (patient monitor). It captures attacker interactions, logs credentials, commands, and IPs, and forwards them to Splunk for visualisation.

## Architecture
[Attacker] → [Cowrie Honeypot] → [Logs] → [Python Parser] → [Splunk]

## Technologies
- Docker (Cowrie honeypot)
- Python (log parsing)
- Splunk (visualisation)
- Kali (testing)

## Setup
1. Install Docker: `sudo apt install docker.io`
2. Deploy Cowrie: `docker run -d --name cowrie -p 2222:2222 -p 2323:2223 -v $(pwd)/data:/cowrie/var -v $(pwd)/logs:/cowrie/log -v $(pwd)/etc:/cowrie/etc cowrie/cowrie:latest`
3. Test: `ssh -p 2222 root@localhost`
4. Parse logs: `python3 parse_logs.py`
5. Send to Splunk: Configure `.env` with HEC token

## Results
- Captured X connections from Y unique IPs
- Top credentials: admin/admin, root/root
- Splunk dashboard shows attack origins

## Author
[Your Name]
"""),

    ("docker-commands.txt", """
# Cowrie Docker Commands

# Deploy honeypot
docker run -d --name cowrie -p 2222:2222 -p 2323:2223 -v $(pwd)/data:/cowrie/var -v $(pwd)/logs:/cowrie/log -v $(pwd)/etc:/cowrie/etc cowrie/cowrie:latest

# View logs
tail -f logs/cowrie.log

# Test SSH
ssh -p 2222 root@localhost

# Test Telnet
telnet localhost 2323

# Stop honeypot
docker stop cowrie

# Start honeypot
docker start cowrie

# Remove honeypot
docker rm -f cowrie

# Enter container
docker exec -it cowrie bash
"""),

    (".env.example", """
SPLUNK_HEC_URL=http://192.168.78.131:8088/services/collector
SPLUNK_HEC_TOKEN=your_splunk_token_here
"""),

    # etc/ files
    ("etc/cowrie.cfg", """
[ssh]
enabled = true
banner_file = /cowrie/etc/banner.txt
hostname = PatientMonitor-Gateway

[telnet]
enabled = true
banner_file = /cowrie/etc/banner.txt

[honeypot]
hostname = PatientMonitor-Gateway
backend = shell

[output_jsonlog]
enabled = true
logfile = /cowrie/log/cowrie.json

[output_textlog]
enabled = true
logfile = /cowrie/log/cowrie.log
"""),

    ("etc/banner.txt", """
***************************************************************
*                                                             *
*   PATIENT MONITORING SYSTEM v2.4.1                         *
*   IoT Medical Gateway - Bedside Unit                       *
*   Serial: PM-2024-8872                                     *
*   Firmware: 2.4.1-iot                                      *
*   Uptime: 247 days, 14 hours                               *
*                                                             *
*   Authorized Personnel Only                                *
*   Unauthorized access is prohibited                        *
*                                                             *
***************************************************************

Welcome to the Patient Monitoring System.
Please log in with your medical credentials.
"""),

    ("etc/userdb.txt", """
root:root
admin:admin
admin:password
admin:123456
root:toor
root:password
admin:admin123
support:support
user:user
doctor:doctor
nurse:nurse
patient:patient
administrator:administrator
"""),

    # Python script
    ("parse_logs.py", """
#!/usr/bin/env python3
import json
import csv
import os
from datetime import datetime

LOG_FILE = "logs/cowrie.json"
OUTPUT_CSV = "iocs.csv"

def parse_cowrie_log():
    events = []
    try:
        with open(LOG_FILE, 'r') as f:
            for line in f:
                try:
                    entry = json.loads(line)
                    eventid = entry.get('eventid')
                    if eventid == 'cowrie.session.connect':
                        events.append({
                            'timestamp': entry.get('timestamp'),
                            'src_ip': entry.get('src_ip'),
                            'action': 'connect'
                        })
                    elif 'login' in eventid:
                        events.append({
                            'timestamp': entry.get('timestamp'),
                            'src_ip': entry.get('src_ip'),
                            'username': entry.get('username'),
                            'password': entry.get('password'),
                            'action': eventid
                        })
                except:
                    pass
    except FileNotFoundError:
        print("No logs found. Run honeypot first.")
        return []
    return events

def main():
    events = parse_cowrie_log()
    print(f"Parsed {len(events)} events")
    if events:
        with open(OUTPUT_CSV, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=events[0].keys())
            writer.writeheader()
            writer.writerows(events)
        print(f"Saved to {OUTPUT_CSV}")

if __name__ == "__main__":
    main()
"""),

    # deploy.sh (executable)
    ("deploy.sh", """#!/bin/bash
echo "Starting Cowrie Honeypot..."
mkdir -p data logs etc
docker run -d --name cowrie -p 2222:2222 -p 2323:2223 -v $(pwd)/data:/cowrie/var -v $(pwd)/logs:/cowrie/log -v $(pwd)/etc:/cowrie/etc cowrie/cowrie:latest
echo "Honeypot running!"
echo "SSH: ssh -p 2222 root@localhost"
echo "Telnet: telnet localhost 2323"
echo "Logs: tail -f logs/cowrie.log"
""", True),  # executable flag
]

# --------------------------------------------------------------------
def create_project():
    os.makedirs(PROJECT_DIR, exist_ok=True)
    os.chdir(PROJECT_DIR)

    for rel_path, content, *executable in FILES:
        # Create directories if needed
        full_path = os.path.join(PROJECT_DIR, rel_path)
        os.makedirs(os.path.dirname(full_path), exist_ok=True)

        # Write file
        with open(full_path, 'w') as f:
            f.write(content.lstrip('\n'))  # strip first newline but preserve formatting

        # Make executable if requested
        if executable:
            st = os.stat(full_path)
            os.chmod(full_path, st.st_mode | stat.S_IEXEC)

    print(f"✅ Project structure created in: {PROJECT_DIR}")
    print("You can now:")
    print("  cd ~/honeypot_project")
    print("  ./deploy.sh          # to start the honeypot")
    print("  python3 parse_logs.py # to parse logs")

if __name__ == "__main__":
    create_project()
