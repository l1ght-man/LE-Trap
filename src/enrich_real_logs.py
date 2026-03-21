#!/usr/bin/env python3
"""
Enrich real-time honeypot logs with threat intelligence
"""

import json
import sys
import os
from pathlib import Path
from datetime import datetime

# Add ml/models to path
sys.path.insert(0, str(Path(__file__).parent.parent / 'ml' / 'models'))

from threat_intelligence import ThreatIntelligence
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

def enrich_real_logs():
    """Enrich real honeypot logs with threat intelligence"""
    
    # Paths
    logs_dir = Path(__file__).parent.parent / 'logs'
    data_dir = Path(__file__).parent.parent / 'data'
    output_file = data_dir / 'enriched_real_attacks.jsonl'
    
    print("=" * 60)
    print("REAL-TIME LOG ENRICHMENT")
    print("=" * 60)
    print(f"📂 Logs directory: {logs_dir}")
    print(f"💾 Output file: {output_file}")
    print()
    
    # Initialize ThreatIntelligence
    api_key = os.getenv('ABUSEIPDB_API_KEY')
    if not api_key:
        print("⚠️  No API key found - will use cache only")
    
    ti = ThreatIntelligence(api_key)
    print(f"[Init] Loaded {len(ti.cache)} cached IPs")
    print()
    
    # Load all real logs
    all_logs = []
    log_files = sorted(logs_dir.glob('honeypot_*.jsonl'))
    
    print(f"📄 Found {len(log_files)} log files:")
    for log_file in log_files:
        count = 0
        with open(log_file, 'r', encoding='utf-8') as f:
            for line in f:
                try:
                    entry = json.loads(line.strip())
                    all_logs.append(entry)
                    count += 1
                except json.JSONDecodeError:
                    continue
        print(f"   ├─ {log_file.name}: {count} entries")
    
    print(f"\n✅ Loaded {len(all_logs)} total real attacks")
    print()
    
    # Get unique IPs
    unique_ips = set()
    for log in all_logs:
        ip = log.get('source_ip')
        if ip:
            unique_ips.add(ip)
    
    print(f"🌐 Found {len(unique_ips)} unique IPs")
    
    # Count how many new IPs need API calls
    new_ips = [ip for ip in unique_ips if ip not in ti.cache and not ti.is_private_ip(ip)]
    print(f"🆕 {len(new_ips)} IPs need API lookup")
    
    if new_ips and not api_key:
        print("⚠️  Cannot lookup new IPs without API key")
    elif new_ips:
        print(f"⚠️  This will use {len(new_ips)} API calls")
        response = input("Continue? (y/n): ").strip().lower()
        if response != 'y':
            print("❌ Cancelled")
            return
    
    print()
    print("🔄 Enriching attacks...")
    
    # Enrich each attack
    enriched_attacks = []
    api_calls_made = 0
    
    for i, attack in enumerate(all_logs, 1):
        enriched = ti.enrich_attack(attack)
        enriched_attacks.append(enriched)
        
        # Check if API call was made
        threat_intel = enriched.get('threat_intelligence', {})
        if threat_intel.get('status') == 'success':
            source_ip = attack.get('source_ip', '')
            if source_ip in new_ips:
                api_calls_made += 1
                new_ips.remove(source_ip)  # Remove so we don't double count
        
        if i % 10 == 0:
            print(f"   ├─ Processed {i}/{len(all_logs)} attacks...")
    
    print(f"✅ Enriched {len(enriched_attacks)} attacks")
    print(f"📡 Made {api_calls_made} new API calls")
    print()
    
    # Save enriched data
    print(f"💾 Saving to {output_file}...")
    with open(output_file, 'w', encoding='utf-8') as f:
        for attack in enriched_attacks:
            f.write(json.dumps(attack) + '\n')
    
    print(f"✅ Saved {len(enriched_attacks)} enriched attacks")
    print()
    
    # Show threat analysis
    print("=" * 60)
    print("THREAT ANALYSIS")
    print("=" * 60)
    
    high_risk = 0
    medium_risk = 0
    low_risk = 0
    tor_ips = 0
    
    for attack in enriched_attacks:
        threat = attack.get('threat_intelligence', {})
        threat_data = threat.get('threat_data', {})
        score = threat_data.get('abuseConfidenceScore', 0)
        
        if score >= 75:
            high_risk += 1
        elif score >= 25:
            medium_risk += 1
        else:
            low_risk += 1
        
        if threat_data.get('isTor'):
            tor_ips += 1
    
    total = len(enriched_attacks)
    print(f"🔴 High Risk (75-100%):   {high_risk:3d} ({high_risk/total*100:5.1f}%)")
    print(f"🟠 Medium Risk (25-74%):  {medium_risk:3d} ({medium_risk/total*100:5.1f}%)")
    print(f"🟢 Low Risk (0-24%):      {low_risk:3d} ({low_risk/total*100:5.1f}%)")
    print(f"🧅 Tor Exit Nodes:        {tor_ips:3d}")
    print()
    
    # Save cache
    ti.save_cache_to_disk()
    print(f"💾 Cache saved with {len(ti.cache)} IPs")
    print()
    print("=" * 60)
    print("✅ ENRICHMENT COMPLETE!")
    print("=" * 60)
    print(f"📊 Dashboard will now show {len(enriched_attacks)} REAL attacks")
    print(f"🔄 Re-run this script when new honeypot logs arrive")

if __name__ == '__main__':
    try:
        enrich_real_logs()
    except KeyboardInterrupt:
        print("\n\n❌ Cancelled by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n\n❌ Error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
