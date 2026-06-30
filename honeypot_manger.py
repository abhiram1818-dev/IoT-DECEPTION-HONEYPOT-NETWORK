#!/usr/bin/env python3
"""
Project 2 - IoT Deception Honeypot Network
Complete automation script for Weeks 2, 3, and 4.

Usage:
    python3 honeypot_manager.py [--deploy] [--test] [--parse] [--splunk] [--all]

Options:
    --deploy   Deploy the Cowrie honeypot container
    --test     Generate test connections (SSH/Telnet)
    --parse    Parse logs and extract IOCs
    --splunk   Send parsed events to Splunk
    --all      Run all steps (default)
"""

import os
import sys
import json
import csv
import subprocess
import time
import socket
from datetime import datetime
from pathlib import Path

# ---------------------------- Configuration ----------------------------
PROJECT_DIR = Path.home() / "honeypot_project"
LOG_DIR = PROJECT_DIR / "logs"
DATA_DIR = PROJECT_DIR / "data"
ETC_DIR = PROJECT_DIR / "etc"
COWRIE_IMAGE = "cowrie/cowrie:latest"
CONTAINER_NAME = "cowrie"

# Splunk config (loaded from .env if present)
SPLUNK_HEC_URL = None
SPLUNK_HEC_TOKEN = None

def load_env():
    global SPLUNK_HEC_URL, SPLUNK_HEC_TOKEN
    env_file = PROJECT_DIR / ".env"
    if env_file.exists():
        with open(env_file) as f:
            for line in f:
                if line.startswith("SPLUNK_HEC_URL="):
                    SPLUNK_HEC_URL = line.split("=", 1)[1].strip()
                elif line.startswith("SPLUNK_HEC_TOKEN="):
                    SPLUNK_HEC_TOKEN = line.split("=", 1)[1].strip()

# ---------------------------- Docker helpers ----------------------------
def docker_installed():
    try:
        subprocess.run(["docker", "--version"], capture_output=True, check=True)
        return True
    except:
        return False

def container_running(name):
    result = subprocess.run(["docker", "ps", "-q", "-f", f"name={name}"], capture_output=True, text=True)
    return bool(result.stdout.strip())

def container_exists(name):
    result = subprocess.run(["docker", "ps", "-aq", "-f", f"name={name}"], capture_output=True, text=True)
    return bool(result.stdout.strip())

def deploy_honeypot():
    print("🐳 Deploying Cowrie honeypot...")
    if not docker_installed():
        print("❌ Docker not installed. Please install: sudo apt install docker.io")
        return False
    # Remove existing container if any
    if container_exists(CONTAINER_NAME):
        subprocess.run(["docker", "rm", "-f", CONTAINER_NAME], capture_output=True)
    # Create directories
    for d in [DATA_DIR, LOG_DIR, ETC_DIR]:
        d.mkdir(parents=True, exist_ok=True)
    # Run container
    cmd = [
        "docker", "run", "-d",
        "--name", CONTAINER_NAME,
        "-p", "2222:2222",
        "-p", "2323:2223",
        "-v", f"{DATA_DIR}:/cowrie/var",
        "-v", f"{LOG_DIR}:/cowrie/log",
        "-v", f"{ETC_DIR}:/cowrie/etc",
        COWRIE_IMAGE
    ]
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        print(f"❌ Failed to start container:\n{result.stderr}")
        return False
    print("✅ Honeypot deployed successfully.")
    print(f"   SSH:  ssh -p 2222 root@localhost")
    print(f"   Telnet: telnet localhost 2323")
    print(f"   Logs: tail -f {LOG_DIR}/cowrie.log")
    return True

def stop_honeypot():
    if container_running(CONTAINER_NAME):
        subprocess.run(["docker", "stop", CONTAINER_NAME], capture_output=True)
        print("🛑 Honeypot stopped.")

# ---------------------------- Test traffic generators ----------------------------
def generate_test_connections():
    """Generate sample SSH and Telnet connections to the honeypot."""
    print("🔧 Generating test connections...")
    if not container_running(CONTAINER_NAME):
        print("❌ Honeypot not running. Please deploy first.")
        return False

    # SSH connection (will fail but logs will show)
    ssh_cmd = ["ssh", "-p", "2222", "-o", "ConnectTimeout=2", "root@localhost"]
    try:
        subprocess.run(ssh_cmd, capture_output=True, timeout=3)
    except subprocess.TimeoutExpired:
        pass  # expected
    except:
        pass

    # Telnet connection
    try:
        import telnetlib
        tn = telnetlib.Telnet("localhost", 2323, timeout=2)
        tn.write(b"root\nadmin\n")
        tn.close()
    except:
        pass

    time.sleep(1)
    print("✅ Test connections sent.")
    return True

# ---------------------------- Log parsing ----------------------------
def parse_logs():
    """Parse cowrie.json and extract IOCs."""
    print("📊 Parsing logs...")
    log_file = LOG_DIR / "cowrie.json"
    if not log_file.exists():
        print("⚠️ No logs found. Generating sample logs...")
        generate_sample_logs()
    events = []
    try:
        with open(log_file, 'r') as f:
            for line in f:
                try:
                    entry = json.loads(line)
                    eventid = entry.get('eventid')
                    ts = entry.get('timestamp')
                    src_ip = entry.get('src_ip')
                    if eventid == 'cowrie.session.connect':
                        events.append({
                            'timestamp': ts,
                            'src_ip': src_ip,
                            'action': 'connect'
                        })
                    elif 'login' in eventid:
                        events.append({
                            'timestamp': ts,
                            'src_ip': src_ip,
                            'username': entry.get('username', ''),
                            'password': entry.get('password', ''),
                            'action': eventid
                        })
                except:
                    pass
    except Exception as e:
        print(f"❌ Error parsing logs: {e}")
        return []

    if events:
        # Save CSV
        csv_path = PROJECT_DIR / "iocs.csv"
        with open(csv_path, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=events[0].keys())
            writer.writeheader()
            writer.writerows(events)
        print(f"✅ Parsed {len(events)} events -> {csv_path}")
    else:
        print("⚠️ No events parsed.")
    return events

def generate_sample_logs():
    """Create sample JSON logs for demonstration."""
    sample_logs = [
        {"eventid": "cowrie.session.connect", "timestamp": "2026-06-30T10:00:00Z", "src_ip": "192.168.1.100"},
        {"eventid": "cowrie.login.failed", "timestamp": "2026-06-30T10:00:05Z", "src_ip": "192.168.1.100", "username": "root", "password": "admin"},
        {"eventid": "cowrie.login.success", "timestamp": "2026-06-30T10:00:10Z", "src_ip": "192.168.1.100", "username": "root", "password": "root"},
        {"eventid": "cowrie.command.input", "timestamp": "2026-06-30T10:00:15Z", "src_ip": "192.168.1.100", "input": "cat /etc/passwd"},
        {"eventid": "cowrie.session.closed", "timestamp": "2026-06-30T10:00:20Z", "src_ip": "192.168.1.100"}
    ]
    log_file = LOG_DIR / "cowrie.json"
    with open(log_file, 'w') as f:
        for entry in sample_logs:
            f.write(json.dumps(entry) + "\n")
    print("📝 Sample logs generated.")

# ---------------------------- Splunk integration ----------------------------
def send_to_splunk(events):
    """Send parsed events to Splunk via HEC."""
    if not SPLUNK_HEC_URL or not SPLUNK_HEC_TOKEN:
        print("⚠️ Splunk not configured. Skipping.")
        return
    try:
        import requests
        headers = {"Authorization": f"Splunk {SPLUNK_HEC_TOKEN}"}
        for ev in events:
            payload = {
                "event": ev,
                "sourcetype": "cowrie"
            }
            resp = requests.post(SPLUNK_HEC_URL, json=payload, headers=headers, verify=False, timeout=5)
            if resp.status_code == 200:
                print(f"✅ Sent event to Splunk: {ev.get('src_ip', '')}")
            else:
                print(f"⚠️ Splunk error: {resp.status_code}")
    except ImportError:
        print("⚠️ Requests module not installed. Install with: pip install requests")
    except Exception as e:
        print(f"❌ Splunk send failed: {e}")

# ---------------------------- Summary report ----------------------------
def generate_summary(events):
    """Generate a summary markdown file for GitHub."""
    if not events:
        events = []
    unique_ips = set(e['src_ip'] for e in events if 'src_ip' in e)
    total_connections = sum(1 for e in events if e.get('action') == 'connect')
    failed_logins = sum(1 for e in events if 'failed' in e.get('action', ''))
    successful_logins = sum(1 for e in events if 'success' in e.get('action', ''))
    creds = {}
    for e in events:
        if 'username' in e and 'password' in e:
            key = f"{e['username']}:{e['password']}"
            creds[key] = creds.get(key, 0) + 1

    report = f"""# Honeypot Results Summary
Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

## Statistics
- Total events parsed: {len(events)}
- Unique attacker IPs: {len(unique_ips)}
- Total connections: {total_connections}
- Failed logins: {failed_logins}
- Successful logins: {successful_logins}

## Top Credentials Attempted
"""
    sorted_creds = sorted(creds.items(), key=lambda x: x[1], reverse=True)[:5]
    for cred, count in sorted_creds:
        report += f"- {cred} (attempted {count} times)\n"

    report += "\n## Top Attacker IPs\n"
    ip_counts = {}
    for e in events:
        if 'src_ip' in e:
            ip_counts[e['src_ip']] = ip_counts.get(e['src_ip'], 0) + 1
    sorted_ips = sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)[:5]
    for ip, count in sorted_ips:
        report += f"- {ip} ({count} events)\n"

    report_path = PROJECT_DIR / "SUMMARY.md"
    with open(report_path, 'w') as f:
        f.write(report)
    print(f"✅ Summary saved to {report_path}")

# ---------------------------- Main ----------------------------
def main():
    os.chdir(PROJECT_DIR)
    load_env()
    args = sys.argv[1:] if len(sys.argv) > 1 else ["--all"]

    if "--all" in args:
        args = ["--deploy", "--test", "--parse", "--splunk"]

    if "--deploy" in args:
        deploy_honeypot()
        time.sleep(2)

    if "--test" in args:
        generate_test_connections()
        time.sleep(1)

    if "--parse" in args:
        events = parse_logs()
        if events and "--splunk" in args:
            send_to_splunk(events)
        if events:
            generate_summary(events)

    print("\n🎉 Done! Check your repository for results.")

if __name__ == "__main__":
    main()
