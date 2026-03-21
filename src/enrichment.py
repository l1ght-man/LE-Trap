"""
Threat Intelligence Enrichment Script

Purpose:
- Load cleaned attack data from data/cleaned_attacks.jsonl
- Extract unique IPs
- Enrich with AbuseIPDB threat intelligence
- Save enriched data to data/enriched_real_attacks.jsonl

Usage:
    python src/enrichment.py
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
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns

print("=" * 70)
print("Threat Intelligence Enrichment - Synthetic Attack Data")
print("=" * 70)

# ===== STEP 1: Initialize Threat Intelligence Client =====
print("\n[1/6] Initializing ThreatIntelligence client...")
api_key = os.getenv('ABUSEIPDB_API_KEY')
if not api_key:
    print("⚠️  WARNING: No API key found. Will use cached data only.")
    
ti = ThreatIntelligence(api_key)
print(f"✅ Initialized with {len(ti.cache)} cached IPs")

# ===== STEP 2: Load Attack Data =====
print("\n[2/6] Loading cleaned real attack data...")

# Paths relative to src/ directory
base_dir = Path(__file__).parent.parent
data_file = base_dir / "data" / "cleaned_attacks.jsonl"

if not data_file.exists():
    print(f"   ℹ️  No cleaned data found, falling back to synthetic...")
    data_file = base_dir / "ml" / "data" / "synthetic_attacks.jsonl"

if not data_file.exists():
    print(f"❌ Error: No attack data found!")
    print("Run src/clean_logs.py first to create cleaned_attacks.jsonl")
    sys.exit(1)

attacks = []
with open(data_file, 'r') as f:
    for line in f:
        try:
            attacks.append(json.loads(line.strip()))
        except json.JSONDecodeError:
            continue

print(f"✅ Loaded {len(attacks):,} attacks from {data_file.name}")

# ===== STEP 3: Extract Unique IPs =====
print("\n[3/6] Extracting unique source IPs...")
all_ips = [attack.get('source_ip') for attack in attacks if attack.get('source_ip')]

# Count IP frequency
from collections import Counter
ip_counter = Counter(all_ips)

# Get top 200 most active IPs only
TOP_N_IPS = 200
top_ips_data = ip_counter.most_common(TOP_N_IPS)
unique_ips = [ip for ip, count in top_ips_data]

print(f"✅ Total unique IPs: {len(ip_counter):,}")
print(f"✅ Processing top {TOP_N_IPS} most active IPs (conserve API quota)")

# Separate public vs private IPs
public_ips = [ip for ip in unique_ips if not ti.is_private_ip(ip)]
private_ips = [ip for ip in unique_ips if ti.is_private_ip(ip)]
print(f"   - Public IPs: {len(public_ips):,} (will lookup)")
print(f"   - Private IPs: {len(private_ips):,} (will skip)")

# ===== STEP 4: Enrich with Threat Data =====
print(f"\n[4/6] Enriching {len(public_ips):,} public IPs with threat data...")
print("⚠️  API quota protection: Will stop at 200 API calls")
print("This may take a while with API calls...")

enriched_count = 0
cache_hits = 0
api_calls = 0
MAX_API_CALLS = 200  # Safety limit

for i, ip in enumerate(public_ips, 1):
    # Check if we'll hit API or cache
    will_use_api = ip not in ti.cache or ti.is_cache_expired(ip)
    
    # Stop if we've hit the API limit
    if will_use_api and api_calls >= MAX_API_CALLS:
        print(f"\n⚠️  Reached API call limit ({MAX_API_CALLS}). Stopping enrichment.")
        print(f"   Already enriched: {enriched_count}/{len(public_ips)} IPs")
        break
    
    # Show progress every 10 IPs
    if i % 10 == 0 or i == 1:
        print(f"   Progress: {i}/{len(public_ips)} | Cache: {cache_hits} | API: {api_calls}", end='\r')
    
    # Get threat data (uses cache or API as needed)
    threat_data = ti.get_threat_data(ip)
    
    if will_use_api:
        api_calls += 1
    else:
        cache_hits += 1
    
    enriched_count += 1

print(f"\n✅ Enriched {enriched_count:,} IPs")
print(f"   - Cache hits: {cache_hits:,}")
print(f"   - API calls made this run: {api_calls:,}")
print(f"   - Remaining quota today: ~{1000 - 106 - api_calls:,} calls (estimate)")

# ===== STEP 5: Enrich All Attacks =====
print("\n[5/6] Enriching all attack records...")
enriched_attacks = []
for attack in attacks:
    enriched = ti.enrich_attack(attack)
    enriched_attacks.append(enriched)

# Save enriched data to data/ (for dashboard)
output_dir = Path(__file__).parent.parent / "data"
output_dir.mkdir(parents=True, exist_ok=True)
output_file = output_dir / "enriched_real_attacks.jsonl"

with open(output_file, 'w') as f:
    for attack in enriched_attacks:
        f.write(json.dumps(attack) + '\n')

print(f"✅ Saved {len(enriched_attacks):,} enriched attacks to {output_file}")

# ===== STEP 6: Generate Threat Analysis =====
print("\n[6/6] Generating threat intelligence analysis...")

# Extract threat scores for analysis
threat_scores = []
threat_by_ip = {}

for attack in enriched_attacks:
    ip = attack.get('source_ip')
    threat_intel = attack.get('threat_intelligence', {})
    
    if threat_intel.get('status') == 'success':
        threat_data = threat_intel.get('threat_data', {})
        score = threat_data.get('abuseConfidenceScore', 0)
        reports = threat_data.get('totalReports', 0)
        
        threat_scores.append(score)
        
        if ip not in threat_by_ip:
            threat_by_ip[ip] = {
                'ip': ip,
                'score': score,
                'reports': reports,
                'country': threat_data.get('countryCode', 'XX'),
                'isp': threat_data.get('isp', 'Unknown'),
                'is_tor': threat_data.get('isTor', False),
                'attacks': 0
            }
        threat_by_ip[ip]['attacks'] += 1

print(f"✅ Analyzed {len(threat_by_ip):,} IPs with threat data")

# Calculate statistics
if threat_scores:
    avg_score = sum(threat_scores) / len(threat_scores)
    print(f"\n📊 Threat Intelligence Statistics:")
    print(f"   - Average abuse score: {avg_score:.1f}%")
    print(f"   - Min score: {min(threat_scores):.0f}%")
    print(f"   - Max score: {max(threat_scores):.0f}%")
    
    # Risk categories
    low_risk = sum(1 for s in threat_scores if s < 25)
    medium_risk = sum(1 for s in threat_scores if 25 <= s < 75)
    high_risk = sum(1 for s in threat_scores if s >= 75)
    
    print(f"\n🚨 Risk Distribution:")
    print(f"   - Low risk (0-24%): {low_risk:,} IPs")
    print(f"   - Medium risk (25-74%): {medium_risk:,} IPs")
    print(f"   - High risk (75-100%): {high_risk:,} IPs")
    
    # Top 10 most dangerous IPs
    top_threats = sorted(threat_by_ip.values(), key=lambda x: x['score'], reverse=True)[:10]
    print(f"\n🔥 Top 10 Most Dangerous IPs:")
    for i, threat in enumerate(top_threats, 1):
        tor_flag = " [TOR]" if threat['is_tor'] else ""
        print(f"   {i}. {threat['ip']:15s} | Score: {threat['score']:3.0f}% | "
              f"Reports: {threat['reports']:3d} | {threat['country']}{tor_flag}")

# ===== STEP 7: Create Visualizations =====
print("\n[7/7] Creating visualizations...")

charts_dir = base_dir / "ml" / "charts"
charts_dir.mkdir(exist_ok=True, parents=True)

# Chart 1: Threat Score Distribution
if threat_scores:
    plt.figure(figsize=(10, 6))
    plt.hist(threat_scores, bins=20, edgecolor='black', color='#e74c3c')
    plt.axvline(avg_score, color='yellow', linestyle='--', linewidth=2, label=f'Average: {avg_score:.1f}%')
    plt.xlabel('Abuse Confidence Score (%)')
    plt.ylabel('Number of IPs')
    plt.title('Threat Score Distribution')
    plt.legend()
    plt.grid(alpha=0.3)
    plt.savefig(charts_dir / 'threat_score_distribution.png', dpi=150, bbox_inches='tight')
    plt.close()
    print(f"✅ Saved: threat_score_distribution.png")

# Chart 2: Risk Category Pie Chart
if threat_scores:
    plt.figure(figsize=(8, 8))
    categories = ['Low Risk\n(0-24%)', 'Medium Risk\n(25-74%)', 'High Risk\n(75-100%)']
    values = [low_risk, medium_risk, high_risk]
    colors = ['#2ecc71', '#f39c12', '#e74c3c']
    
    plt.pie(values, labels=categories, autopct='%1.1f%%', colors=colors, startangle=90)
    plt.title('IP Risk Distribution')
    plt.savefig(charts_dir / 'risk_categories.png', dpi=150, bbox_inches='tight')
    plt.close()
    print(f"✅ Saved: risk_categories.png")

# Chart 3: Top 10 Threat IPs Bar Chart
if top_threats:
    plt.figure(figsize=(12, 6))
    ips = [t['ip'] for t in top_threats]
    scores = [t['score'] for t in top_threats]
    colors_bar = ['#e74c3c' if s >= 75 else '#f39c12' if s >= 25 else '#2ecc71' for s in scores]
    
    plt.barh(ips, scores, color=colors_bar, edgecolor='black')
    plt.xlabel('Abuse Confidence Score (%)')
    plt.ylabel('IP Address')
    plt.title('Top 10 Most Dangerous IPs')
    plt.xlim(0, 100)
    plt.grid(axis='x', alpha=0.3)
    plt.tight_layout()
    plt.savefig(charts_dir / 'top_threats.png', dpi=150, bbox_inches='tight')
    plt.close()
    print(f"✅ Saved: top_threats.png")

print("\n" + "=" * 70)
print("✅ Threat Enrichment Complete!")
print("=" * 70)
print(f"\n📁 Output Files:")
print(f"   - Enriched data: {output_file}")
print(f"   - Charts: {charts_dir}/")
print(f"   - Cache: {ti.cache_file}")
print(f"\n📊 Summary:")
print(f"   - Total attacks processed: {len(enriched_attacks):,}")
print(f"   - Unique IPs enriched: {len(threat_by_ip):,}")
print(f"   - API calls made: {api_calls:,}")
print(f"   - Cache entries: {len(ti.cache):,}")
