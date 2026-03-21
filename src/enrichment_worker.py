#!/usr/bin/env python3
"""
Threat Intelligence Enrichment Worker
Extracted function for use by daemon and standalone runs.
"""

import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'ml', 'models'))

from dotenv import load_dotenv
load_dotenv()

from threat_intelligence import ThreatIntelligence
import json
from pathlib import Path
from collections import Counter

def enrich_real_attacks():
    """
    Enrich real honeypot attacks with threat intelligence.
    Can be called from daemon or standalone.
    """
    
    # Initialize
    base_dir = Path(__file__).parent.parent
    api_key = os.getenv('ABUSEIPDB_API_KEY')
    ti = ThreatIntelligence(api_key)
    
    # Load cleaned data
    data_file = base_dir / "data" / "cleaned_attacks.jsonl"
    if not data_file.exists():
        print(f"   ℹ️  No cleaned data found")
        return False
    
    attacks = []
    with open(data_file, 'r') as f:
        for line in f:
            try:
                attacks.append(json.loads(line.strip()))
            except json.JSONDecodeError:
                continue
    
    if not attacks:
        print(f"   ℹ️  No attacks to enrich")
        return False
    
    print(f"   ✓ Loaded {len(attacks):,} cleaned attacks")
    
    # Extract unique IPs
    all_ips = [a.get('source_ip') for a in attacks if a.get('source_ip')]
    ip_counter = Counter(all_ips)
    unique_ips = [ip for ip, _ in ip_counter.most_common(200)]
    
    public_ips = [ip for ip in unique_ips if not ti.is_private_ip(ip)]
    private_ips = [ip for ip in unique_ips if ti.is_private_ip(ip)]
    
    print(f"   ✓ Found {len(public_ips)} public IPs, {len(private_ips)} private IPs")
    
    # Enrich with threat data
    enriched_count = 0
    cache_hits = 0
    api_calls = 0
    MAX_API_CALLS = 100
    
    for i, ip in enumerate(public_ips, 1):
        will_use_api = ip not in ti.cache or ti.is_cache_expired(ip)
        
        if will_use_api and api_calls >= MAX_API_CALLS:
            print(f"   ⚠️  API limit reached ({MAX_API_CALLS})")
            break
        
        threat_data = ti.get_threat_data(ip)
        
        if will_use_api:
            api_calls += 1
        else:
            cache_hits += 1
        
        enriched_count += 1
        
        if i % 20 == 0:
            print(f"   Progress: {i}/{len(public_ips)} | Cache: {cache_hits} | API: {api_calls}", end='\r')
    
    print(f"\n   ✓ Enriched {enriched_count} IPs (Cache: {cache_hits}, API: {api_calls})")
    
    # Enrich all attacks
    enriched_attacks = []
    for attack in attacks:
        enriched = ti.enrich_attack(attack)
        enriched_attacks.append(enriched)
    
    # Save enriched data
    output_dir = base_dir / "data"
    output_dir.mkdir(parents=True, exist_ok=True)
    output_file = output_dir / "enriched_real_attacks.jsonl"
    
    with open(output_file, 'w') as f:
        for attack in enriched_attacks:
            f.write(json.dumps(attack) + '\n')
    
    print(f"   ✓ Saved {len(enriched_attacks):,} enriched attacks")
    return True

if __name__ == '__main__':
    enrich_real_attacks()
