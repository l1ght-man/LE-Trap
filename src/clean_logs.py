#!/usr/bin/env python3
"""
Clean honeypot logs for ML model input.
Removes noise, standardizes format, extracts credentials.
"""

import json
import glob
from pathlib import Path
from datetime import datetime
import re

SCRIPT_DIR = Path(__file__).parent.resolve()
LOG_DIR = SCRIPT_DIR.parent / "logs"
OUTPUT_FILE = SCRIPT_DIR.parent / "data" / "cleaned_attacks.jsonl"

# Event types to KEEP
KEEP_EVENTS = {
    'Telnet login attempt',
    'HTTP_REQUEST',
    'USER_AGENT',
    'FTP_LOGIN',
    'SSH_LOGIN',
    'CREDENTIAL_SUBMISSION',
    'FTP login attempt',
    'SSH login attempt',
}

# Events starting with these prefixes to KEEP
KEEP_PREFIXES = [
    'LOGIN ATTEMPT:',
    'CMD:',
    'USER:',
    'PASS:',
    'Successful authentication',
]

# Events to FILTER (noise)
FILTER_PATTERNS = [
    r'^Error',
    r'^DOCKER_ERROR',
    r'^banner',
    r'^FTP-COMMAND',
    r'WinError',
    r'Socket is closed',
    r'established connection was aborted',
]

def should_keep_event(event_type):
    """Check if event should be kept"""
    if event_type in KEEP_EVENTS:
        return True
    
    for prefix in KEEP_PREFIXES:
        if event_type.startswith(prefix):
            return True
    
    for pattern in FILTER_PATTERNS:
        if re.search(pattern, event_type):
            return False
    
    return False

def extract_credentials(event_type, details):
    """Extract username/password from login attempts"""
    creds = {}
    
    # Format: "LOGIN ATTEMPT: username password"
    match = re.search(r'LOGIN ATTEMPT:\s+(\S+)\s+(\S+)', event_type)
    if match:
        creds['username'] = match.group(1)
        creds['password'] = match.group(2)
    
    # Format: "USER: username" on separate lines
    if 'USER:' in event_type:
        match = re.search(r'USER:\s+(\S+)', event_type)
        if match:
            creds['username'] = match.group(1)
    
    if 'PASS:' in event_type:
        match = re.search(r'PASS:\s+(\S+)', event_type)
        if match:
            creds['password'] = match.group(1)
    
    return creds if creds else None

def extract_command(event_type):
    """Extract command from CMD: prefix"""
    match = re.search(r'CMD:\s+(.+)', event_type)
    return match.group(1) if match else None

def clean_log_entry(entry):
    """Clean and standardize a single log entry"""
    event_type = entry.get('event_type', '').strip()
    
    # Filter out noise
    if not should_keep_event(event_type):
        return None
    
    # Build cleaned entry
    cleaned = {
        'timestamp': entry.get('timestamp'),
        'source_ip': entry.get('source_ip'),
        'port': entry.get('port'),
        'service': entry.get('service', '').lower(),
        'event_type': event_type,
    }
    
    # Extract credentials if present
    creds = extract_credentials(event_type, entry.get('details', ''))
    if creds:
        cleaned['credentials'] = creds
    
    # Extract command if present
    cmd = extract_command(event_type)
    if cmd:
        cleaned['command'] = cmd
    
    # Keep details if non-empty and not noise
    if entry.get('details') and not any(
        re.search(p, entry.get('details', '')) for p in FILTER_PATTERNS
    ):
        cleaned['details'] = entry.get('details')
    
    return cleaned

def clean_logs():
    """Clean all honeypot logs"""
    log_files = sorted(glob.glob(str(LOG_DIR / "honeypot_*.jsonl")))
    
    if not log_files:
        print(f"[!] No log files found in {LOG_DIR}")
        return
    
    cleaned_count = 0
    filtered_count = 0
    
    print(f"[*] Processing {len(log_files)} log file(s)...")
    print(f"[*] Writing to: {OUTPUT_FILE}")
    
    with open(OUTPUT_FILE, 'w', encoding='utf-8') as out_f:
        for log_file in log_files:
            print(f"\n[*] Reading: {log_file}")
            
            try:
                with open(log_file, 'r', encoding='utf-8') as in_f:
                    for line in in_f:
                        try:
                            entry = json.loads(line.strip())
                            cleaned = clean_log_entry(entry)
                            
                            if cleaned:
                                out_f.write(json.dumps(cleaned) + '\n')
                                cleaned_count += 1
                            else:
                                filtered_count += 1
                        
                        except json.JSONDecodeError:
                            filtered_count += 1
                            continue
            
            except FileNotFoundError:
                print(f"  [!] File not found: {log_file}")
                continue
    
    print(f"\n[+] CLEANING COMPLETE")
    print(f"    Kept:     {cleaned_count} events")
    print(f"    Filtered: {filtered_count} events (noise)")
    print(f"    Output:   {OUTPUT_FILE}")

if __name__ == '__main__':
    clean_logs()
