"""Quick stats check for synthetic data"""
import json
from collections import Counter

with open('data/synthetic_attacks.jsonl') as f:
    logs = [json.loads(line) for line in f]

print(f'Total attacks: {len(logs):,}')
print(f'Date range: {logs[0]["timestamp"]} to {logs[-1]["timestamp"]}')
print(f'\nEvent types:')
for event, count in Counter(l['event_type'] for l in logs).items():
    print(f'  {event}: {count:,}')
print(f'\nServices:')
for svc, count in Counter(l['service'] for l in logs).items():
    print(f'  {svc}: {count:,}')
print(f'\nUnique IPs: {len(set(l["source_ip"] for l in logs)):,}')
