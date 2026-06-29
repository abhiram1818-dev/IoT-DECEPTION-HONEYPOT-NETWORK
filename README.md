

Infotact Technical Internship Program – Cybersecurity Project (Healthcare)
📌 Project Overview

The IoT Deception Honeypot Network is a proactive cybersecurity defence system designed to protect healthcare environments from cyber attacks targeting connected medical devices.

Instead of waiting for attackers to find real devices, this system deploys decoy (fake) IoT devices that mimic real medical equipment (patient monitors, smart HVAC systems, etc.). When attackers interact with these decoys, their behaviour, IP addresses, and attack techniques are captured, logged, and analysed – without any risk to actual hospital infrastructure.

This project demonstrates a deception-based threat intelligence approach, shifting from reactive to proactive defence.
🎯 Key Features
Week	Feature
Week 1	Docker setup, Cowrie honeypot deployment, IoT device simulation (open ports, custom banners)
Week 2	Controlled exposure, testing with Kali, live log capture (connections, login attempts)
Week 3	Log parsing with Python, IOC extraction (IPs, credentials, uploaded files, commands)
Week 4	Splunk dashboard (attack origins, top attackers, geolocation), final report
Additional Capabilities

    🏥 IoT Device Simulation – mimics real medical devices (default credentials, custom banners)

    🔒 Isolation – Docker ensures attackers cannot escape the sandboxed environment

    📊 Log Parsing – extracts attacker IPs, usernames, passwords, and executed commands

    🌍 Geolocation Analysis – maps attack origins on a world map

    📈 Splunk Integration – visualises attack patterns, top attackers, and exploit techniques

    🛡️ Safe by Design – no real data or systems are exposed to risk

🏗️ Architecture Diagram
text

[Internet / Attacker] → [Honeypot Server] → [Cowrie Honeypot] → [Logs (JSON)]
                                ↓                    ↓
                         [Docker Isolation]    [Python Parser]
                                                     ↓
                                                [Splunk Dashboard]
                                                (IPs, credentials, commands)

Components Explained
Component	Description
Cowrie Honeypot	Open‑source SSH/Telnet honeypot; logs all attacker interactions
Docker	Provides strict isolation – prevents escape to the host system
IoT Simulation	Custom banners, open ports, and fake file systems mimicking medical devices
Python Parser	Extracts IOCs (IPs, credentials, file hashes, commands) from raw logs
Splunk SIEM	Visualises attack origins, most targeted services, and attacker behaviour
Kali VM	Used for controlled testing and simulation of real attacks
💻 Technology Stack
Component	Technology
Honeypot Software	Cowrie (low‑interaction)
Isolation	Docker (containers)
Log Parsing	Python (json, csv, requests)
SIEM	Splunk Enterprise (HTTP Event Collector)
Visualisation	Splunk Dashboard
Virtualisation	VMware (Ubuntu + Kali + Windows 10)
Testing Tool	Kali Linux (SSH, Telnet, Metasploit)
Version Control	Git + GitHub
🛠️ Setup Instructions (Ubuntu VM)
Prerequisites

    Ubuntu 22.04 / 24.04

    Docker installed

    Python 3.10+ and pip

    Splunk Enterprise on separate Windows VM (free license)

    Kali VM for testing (optional)

Step 1: Install Docker
bash

sudo apt update && sudo apt upgrade -y
sudo apt install docker.io -y
sudo systemctl start docker && sudo systemctl enable docker
sudo usermod -aG docker $USER   # log out and back in
docker --version

Step 2: Deploy Cowrie Honeypot
bash

mkdir ~/cowrie
cd ~/cowrie

docker run -d \
  --name cowrie \
  -p 22:2222 \
  -p 23:2223 \
  -v $(pwd)/data:/cowrie/var \
  -v $(pwd)/logs:/cowrie/log \
  cowrie/cowrie:latest

Step 3: Customise IoT Device Simulation

Enter the container:
bash

docker exec -it cowrie bash

Create a realistic IoT banner:
bash

echo "Ubuntu 18.04.6 LTS (IoT Gateway - Patient Monitor)" > /cowrie/etc/banner.txt

Edit cowrie.cfg to enable Telnet and custom banner:
bash

vi /cowrie/etc/cowrie.cfg

ini

[ssh]
banner_file = /cowrie/etc/banner.txt

[telnet]
enabled = true

Restart the container:
bash

docker restart cowrie

Step 4: Test with Kali (internal network)

From Kali VM, test the honeypot:
bash

# SSH attempt (any credentials accepted)
ssh -p 2222 root@<ubuntu-ip>
# Password: any

# Telnet attempt
telnet <ubuntu-ip> 23

Check logs:
bash

tail -f ~/cowrie/logs/cowrie.log

Step 5: Parse Logs with Python

Create parse_logs.py (see code below).
Step 6: Send to Splunk

Configure .env:
bash

cat > .env << EOF
SPLUNK_HEC_URL=http://your_windows_ip:8088/services/collector
SPLUNK_HEC_TOKEN=your_splunk_token
EOF

Step 7: Splunk Dashboard (Week 4)

    Search: index=main sourcetype=cowrie

    Create panels:

        Top attacking IPs (pie chart)

        Credentials used (table)

        Time chart of connections

📊 Project Results
Sample Logs from Cowrie
text

[2026-05-15 10:30:22] Connection from 192.168.1.100:54321
[2026-05-15 10:30:25] Login attempt: root / admin123
[2026-05-15 10:30:28] Command executed: cat /etc/passwd

Parsed IOCs (Example)
Timestamp	Source IP	Username	Password	Action
2026-05-15 10:30:22	192.168.1.100	-	-	Connection
2026-05-15 10:30:25	192.168.1.100	root	admin123	Login Attempt
2026-05-15 10:30:28	192.168.1.100	root	admin123	Command: cat /etc/passwd
Splunk Dashboard

    Top 10 Attacking IPs – bar chart

    Credentials Used – table with username/password combinations

    Time Trend – connections over time

    Geolocation Map (optional) – shows attack origins

🧪 Testing with Kali (Week 2)
Simulate an Attack:
bash

# SSH Bruteforce (using Hydra)
hydra -l root -P /usr/share/wordlists/rockyou.txt ssh://<ubuntu-ip>:2222

# Telnet Connection
telnet <ubuntu-ip> 23

Verify Logs:
bash

tail -f ~/cowrie/logs/cowrie.log

🐍 Full Python Parser Code (parse_logs.py)
python

#!/usr/bin/env python3
"""
Week 3 - Parse Cowrie logs, extract IOCs, and send to Splunk.
"""

import json
import csv
import os
import requests
from datetime import datetime
from dotenv import load_dotenv

load_dotenv()

LOG_FILE = "logs/cowrie.log"
OUTPUT_CSV = "iocs.csv"
SPLUNK_HEC_URL = os.getenv("SPLUNK_HEC_URL")
SPLUNK_HEC_TOKEN = os.getenv("SPLUNK_HEC_TOKEN")

def parse_cowrie_log(log_path):
    events = []
    with open(log_path, 'r') as f:
        for line in f:
            try:
                entry = json.loads(line)
                eventid = entry.get('eventid')
                ts = entry.get('timestamp')
                src_ip = entry.get('src_ip')
                dst_port = entry.get('dst_port')
                
                if eventid == 'cowrie.session.connect':
                    events.append({
                        'timestamp': ts,
                        'src_ip': src_ip,
                        'dst_port': dst_port,
                        'action': 'connect'
                    })
                elif eventid == 'cowrie.login.success':
                    username = entry.get('username')
                    password = entry.get('password')
                    events.append({
                        'timestamp': ts,
                        'src_ip': src_ip,
                        'username': username,
                        'password': password,
                        'action': 'login_success'
                    })
                elif eventid == 'cowrie.login.failed':
                    username = entry.get('username')
                    password = entry.get('password')
                    events.append({
                        'timestamp': ts,
                        'src_ip': src_ip,
                        'username': username,
                        'password': password,
                        'action': 'login_failed'
                    })
                elif 'command' in entry:
                    events.append({
                        'timestamp': ts,
                        'src_ip': src_ip,
                        'command': entry.get('input'),
                        'action': 'command_executed'
                    })
            except:
                continue
    return events

def send_to_splunk(event):
    if not SPLUNK_HEC_URL or not SPLUNK_HEC_TOKEN:
        return
    headers = {"Authorization": f"Splunk {SPLUNK_HEC_TOKEN}"}
    try:
        requests.post(SPLUNK_HEC_URL, json=event, headers=headers, verify=False, timeout=5)
    except:
        pass

def main():
    events = parse_cowrie_log(LOG_FILE)
    print(f"Parsed {len(events)} events")
    
    # Save CSV
    if events:
        with open(OUTPUT_CSV, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=events[0].keys())
            writer.writeheader()
            writer.writerows(events)
        print(f"Saved to {OUTPUT_CSV}")
    
    # Send to Splunk
    for ev in events:
        send_to_splunk({
            "event": ev,
            "sourcetype": "cowrie"
        })
    print("Done.")

if __name__ == "__main__":
    main()

🛡️ Safety & Ethics

    Isolation: Docker ensures attackers cannot escape the honeypot.

    No Real Data: Cowrie uses fake credentials and file systems.

    Legal: Deploying honeypots is legal for research purposes in most jurisdictions.

    Do Not Attack Back: Never retaliate against attackers.

    Monitor Carefully: Review logs daily to ensure no unexpected behaviour.

⚠️ Challenges & Solutions
Challenge	Solution
Cowrie not logging properly	Checked volume mounts and ensured logs/ directory is writable.
Attacker escaping container	Used Docker with minimal privileges and isolated network.
Splunk HEC connection refused	Opened Windows Firewall port 8088, disabled SSL.
Large log files	Implemented log rotation and cron job to archive old logs.
Too many false positives	Reduced exposure scope; tested only on internal network.
IP geolocation in Splunk	Used iplocation command in Splunk search.
🚀 Future Enhancements

    🌐 Public Exposure – Deploy on a cloud server to collect real-world attack data.

    🤖 High-Interaction Honeypot – Simulate more complex device behaviour (Dionaea, Conpot).

    🧠 Machine Learning – Detect attack patterns and predict zero-day exploits.

    📱 Mobile Alerts – Send push notifications for critical attacks (Telegram bot).

    🔗 Threat Intelligence Sharing – Submit IOCs to MISP or other threat-sharing platforms.

📂 Repository Structure
text

cowrie/
├── data/                         # Persistent Cowrie data
├── logs/                         # Cowrie log files (cowrie.log, json.log)
├── parse_logs.py                 # Python script to parse logs
├── iocs.csv                      # Extracted IOCs (CSV format)
├── .env                          # Splunk credentials (ignored)
├── .gitignore                    # Excludes logs, .env
├── README.md                     # Project documentation
├── FINAL_REPORT.md               # Detailed final report
└── docker-compose.yml            # (Optional) Docker Compose for Cowrie

🙏 Acknowledgements

    Infotact Solutions – For the internship opportunity and project guidance.

    Cowrie Project – For the open‑source SSH/Telnet honeypot.

    Docker – For containerisation and isolation.

    Splunk – For the free developer license and SIEM capabilities.

    Kali Linux – For penetration testing tools.

📬 Contact

For questions or collaboration:

    GitHub: https://github.com/your-username/iot-honeypot

    Email: [your-email@example.com]

📸 Sample Splunk Dashboard
Panel	Description
Top 10 Attacking IPs	Bar chart of IPs with most connections
Credentials Used	Table of username/password attempts
Connections Over Time	Time trend of attack volume
Geolocation Map	World map showing attack origins
Commands Executed	List of commands run by attackers
📝 Final Words

    "This project demonstrates how deception-based defence can provide early warning, threat intelligence, and actionable insights – all without risking real medical devices. It’s a critical tool for protecting healthcare environments against evolving cyber threats."


