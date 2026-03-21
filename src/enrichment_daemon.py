#!/usr/bin/env python3
"""
ML Enrichment Daemon
Runs threat intelligence enrichment on a schedule.
Watches for new cleaned logs and enriches them continuously.
"""

import time
import sys
import os
from pathlib import Path
from datetime import datetime

# Add ML models to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'ml', 'models'))

from dotenv import load_dotenv
load_dotenv()

print("=" * 70)
print("ML ENRICHMENT DAEMON")
print("=" * 70)

# Configurable intervals
ENRICHMENT_INTERVAL = 60  # Run enrichment every 60 seconds
CHECK_INTERVAL = 5  # Check for new data every 5 seconds

def run_cleaner():
    """Run the log cleaner"""
    print(f"\n[{datetime.now().strftime('%H:%M:%S')}] Running log cleaner...")
    try:
        from clean_logs import clean_logs
        clean_logs()
        print(f"[{datetime.now().strftime('%H:%M:%S')}] ✓ Log cleaning complete")
        return True
    except Exception as e:
        print(f"[{datetime.now().strftime('%H:%M:%S')}] ✗ Log cleaning failed: {e}")
        import traceback
        traceback.print_exc()
        return False

def run_enrichment():
    """Run the enrichment script"""
    print(f"\n[{datetime.now().strftime('%H:%M:%S')}] Running enrichment...")
    try:
        from enrichment_worker import enrich_real_attacks
        enrich_real_attacks()
        print(f"[{datetime.now().strftime('%H:%M:%S')}] ✓ Enrichment complete")
        return True
    except Exception as e:
        print(f"[{datetime.now().strftime('%H:%M:%S')}] ✗ Enrichment failed: {e}")
        import traceback
        traceback.print_exc()
        return False

def run_pipeline():
    """Run full pipeline: clean → enrich"""
    print(f"\n[{datetime.now().strftime('%H:%M:%S')}] >>> RUNNING FULL PIPELINE <<<")
    run_cleaner()
    run_enrichment()
    print(f"[{datetime.now().strftime('%H:%M:%S')}] >>> PIPELINE COMPLETE <<<\n")

def main():
    """Main daemon loop"""
    print(f"[INFO] Starting enrichment daemon...")
    print(f"[INFO] Enrichment interval: {ENRICHMENT_INTERVAL}s")
    print(f"[INFO] Check interval: {CHECK_INTERVAL}s")
    print(f"[INFO] Pipeline steps: clean_logs → enrich_attacks")
    
    last_enrichment = 0
    
    try:
        while True:
            now = time.time()
            
            # Run full pipeline at regular intervals
            if now - last_enrichment >= ENRICHMENT_INTERVAL:
                run_pipeline()
                last_enrichment = now
            
            # Sleep before next check
            time.sleep(CHECK_INTERVAL)
    
    except KeyboardInterrupt:
        print("\n[INFO] Daemon stopped by user")
        sys.exit(0)
    except Exception as e:
        print(f"[ERROR] Daemon error: {e}")
        sys.exit(1)

if __name__ == '__main__':
    main()
