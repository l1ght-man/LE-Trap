import json
import sys
sys.path.insert(0, 'src')
from dashboard import calculate_statistics, load_all_logs

logs = load_all_logs()
print(f'Total logs: {len(logs)}')

stats = calculate_statistics(logs)
print(f'Threat IPs found: {len(stats.get("threat_ips", []))}')

if stats.get('threat_ips'):
    print('\nTop 5 threat IPs:')
    for item in stats['threat_ips'][:5]:
        print(f'  {item["ip"]}: {item["abuse_score"]}% TOR={item.get("is_tor", False)}')
else:
    print('No threat_ips in stats')
    print(f'Stats keys: {stats.keys()}')
