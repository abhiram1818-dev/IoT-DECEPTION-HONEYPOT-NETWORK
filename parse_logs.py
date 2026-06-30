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
