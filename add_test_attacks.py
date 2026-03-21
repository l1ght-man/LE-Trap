#!/usr/bin/env python3
"""Add test attacks from public IPs around the world"""

import json
from datetime import datetime
from pathlib import Path

# Test IPs from different locations around the world
test_attacks = [
    {"ip": "8.8.8.8", "country": "USA", "service": "ssh"},  # Google DNS
    {"ip": "1.1.1.1", "country": "Australia", "service": "ssh"},  # Cloudflare
    {"ip": "185.220.101.1", "country": "Germany", "service": "telnet"},  # Tor exit node
    {"ip": "45.142.212.61", "country": "Russia", "service": "ssh"},  # Random
    {"ip": "103.224.182.245", "country": "Singapore", "service": "ftp"},  # Random
    {"ip": "200.55.82.10", "country": "Brazil", "service": "http"},  # Random
    {"ip": "41.60.232.145", "country": "South Africa", "service": "ssh"},  # Random
]

log_file = Path("logs/honeypot_2026-02-10.jsonl")

with open(log_file, 'a', encoding='utf-8') as f:
    for attack in test_attacks:
        entry = {
            "timestamp": datetime.now().isoformat(),
            "source_ip": attack["ip"],
            "port": 22 if attack["service"] == "ssh" else 21,
            "service": attack["service"],
            "event_type": "login attempt",
            "details": f"Test attack from {attack['country']}"
        }
        f.write(json.dumps(entry) + '\n')

print(f"✅ Added {len(test_attacks)} test attacks from around the world!")
print("\n🌍 Test IPs added:")
for attack in test_attacks:
    print(f"  - {attack['ip']} ({attack['country']})")
