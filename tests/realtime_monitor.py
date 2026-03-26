#!/usr/bin/env python3
"""
Real-time Attack Monitor with IP Flagging
Monitors honeypot logs and displays high-threat IPs in real-time
"""

import json
import time
import os
from pathlib import Path
from datetime import datetime
from collections import defaultdict
from typing import Dict, List, Set

# ANSI color codes for terminal
class Colors:
    RED = '\033[91m'
    YELLOW = '\033[93m'
    GREEN = '\033[92m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    RESET = '\033[0m'

# Configuration
LOG_DIR = Path("logs")
THREAT_CACHE = Path("data/threat_cache.json")
HIGH_THREAT_THRESHOLD = 50  # AbuseIPDB confidence score
BOT_TIME_THRESHOLD = 2.0  # seconds between attacks

class RealtimeMonitor:
    def __init__(self):
        self.seen_attacks = set()  # Track processed attack IDs
        self.ip_stats = defaultdict(lambda: {
            'count': 0,
            'ports': set(),
            'services': set(),
            'credentials': set(),
            'threat_score': 0,
            'is_tor': False,
            'last_seen': None,
            'is_bot': False,
            'attack_times': []
        })
        self.threat_cache = self._load_threat_cache()
        self.flagged_ips = set()
        self.total_attacks = 0
        self.start_time = time.time()
    
    def _load_threat_cache(self) -> Dict:
        """Load cached threat intelligence data"""
        if THREAT_CACHE.exists():
            try:
                with open(THREAT_CACHE, 'r') as f:
                    return json.load(f)
            except:
                pass
        return {}
    
    def _get_attack_id(self, attack: Dict) -> str:
        """Generate unique ID for attack"""
        return f"{attack['timestamp']}_{attack['source_ip']}_{attack.get('event_type', '')}"
    
    def _classify_bot(self, ip: str) -> bool:
        """Simple bot classification based on timing"""
        stats = self.ip_stats[ip]
        if len(stats['attack_times']) < 2:
            return False
        
        # Calculate average time between attacks
        times = sorted(stats['attack_times'])
        intervals = [times[i+1] - times[i] for i in range(len(times)-1)]
        avg_interval = sum(intervals) / len(intervals) if intervals else 999
        
        return avg_interval < BOT_TIME_THRESHOLD
    
    def _get_threat_score(self, ip: str) -> int:
        """Get threat score from cache"""
        threat_data = self.threat_cache.get(ip, {})
        return threat_data.get('abuseConfidenceScore', 0)
    
    def _is_tor(self, ip: str) -> bool:
        """Check if IP is Tor exit node"""
        threat_data = self.threat_cache.get(ip, {})
        return threat_data.get('isTor', False)
    
    def _flag_ip(self, ip: str) -> bool:
        """Determine if IP should be flagged"""
        stats = self.ip_stats[ip]
        
        # Flag criteria
        if stats['threat_score'] >= HIGH_THREAT_THRESHOLD:
            return True
        if stats['is_tor']:
            return True
        if stats['count'] >= 10:  # High volume
            return True
        if stats['is_bot'] and stats['count'] >= 5:  # Active bot
            return True
        
        return False
    
    def _format_ip_display(self, ip: str) -> str:
        """Format IP with color coding based on threat level"""
        stats = self.ip_stats[ip]
        threat = stats['threat_score']
        
        if threat >= 75 or stats['is_tor']:
            color = Colors.RED + Colors.BOLD
            flag = "🚨 CRITICAL"
        elif threat >= 50:
            color = Colors.RED
            flag = "⚠️  HIGH"
        elif threat >= 25:
            color = Colors.YELLOW
            flag = "⚡ MEDIUM"
        else:
            color = Colors.CYAN
            flag = "ℹ️  LOW"
        
        bot_indicator = f"{Colors.MAGENTA}[BOT]{Colors.RESET}" if stats['is_bot'] else "[HUMAN]"
        tor_indicator = f"{Colors.RED}[TOR]{Colors.RESET}" if stats['is_tor'] else ""
        
        return f"{color}{flag:12} {ip:15} {Colors.RESET}{bot_indicator} {tor_indicator}"
    
    def process_attack(self, attack: Dict):
        """Process a single attack entry"""
        attack_id = self._get_attack_id(attack)
        
        # Skip if already processed
        if attack_id in self.seen_attacks:
            return
        
        self.seen_attacks.add(attack_id)
        self.total_attacks += 1
        
        ip = attack['source_ip']
        timestamp = datetime.fromisoformat(attack['timestamp'].replace('Z', '+00:00'))
        
        # Update IP statistics
        stats = self.ip_stats[ip]
        stats['count'] += 1
        stats['ports'].add(attack.get('port', 'unknown'))
        stats['services'].add(attack.get('service', 'unknown'))
        stats['last_seen'] = timestamp
        stats['attack_times'].append(timestamp.timestamp())
        
        # Extract credentials
        if 'password' in attack.get('details', ''):
            try:
                cred = attack['details'].split('password=')[1].split()[0]
                stats['credentials'].add(cred[:20])  # Limit length
            except:
                pass
        
        # Get threat intelligence
        stats['threat_score'] = self._get_threat_score(ip)
        stats['is_tor'] = self._is_tor(ip)
        stats['is_bot'] = self._classify_bot(ip)
        
        # Check if should be flagged
        if self._flag_ip(ip):
            if ip not in self.flagged_ips:
                self.flagged_ips.add(ip)
                self._display_new_flag(ip)
    
    def _display_new_flag(self, ip: str):
        """Display alert for newly flagged IP"""
        stats = self.ip_stats[ip]
        
        print(f"\n{Colors.BOLD}{'='*80}{Colors.RESET}")
        print(f"{Colors.RED + Colors.BOLD}🚩 NEW FLAGGED IP DETECTED{Colors.RESET}")
        print(f"{'='*80}")
        print(self._format_ip_display(ip))
        print(f"  Attacks: {Colors.BOLD}{stats['count']}{Colors.RESET}")
        print(f"  Ports: {', '.join(map(str, stats['ports']))}")
        print(f"  Services: {', '.join(stats['services'])}")
        if stats['credentials']:
            print(f"  Credentials tried: {len(stats['credentials'])}")
        print(f"  Threat Score: {Colors.RED}{stats['threat_score']}%{Colors.RESET}")
        print(f"{'='*80}\n")
    
    def display_dashboard(self):
        """Display real-time dashboard"""
        os.system('cls' if os.name == 'nt' else 'clear')
        
        runtime = time.time() - self.start_time
        
        print(f"{Colors.BOLD + Colors.CYAN}")
        print("="*80)
        print("  LE-TRAP REAL-TIME ATTACK MONITOR - FLAGGED IPs")
        print("="*80)
        print(f"{Colors.RESET}")
        
        print(f"{Colors.GREEN}Runtime:{Colors.RESET} {int(runtime)}s  ", end='')
        print(f"{Colors.GREEN}Total Attacks:{Colors.RESET} {self.total_attacks}  ", end='')
        print(f"{Colors.RED}Flagged IPs:{Colors.RESET} {len(self.flagged_ips)}")
        print()
        
        if not self.flagged_ips:
            print(f"{Colors.YELLOW}No flagged IPs yet... monitoring...{Colors.RESET}")
            return
        
        # Sort IPs by threat score (descending)
        sorted_ips = sorted(
            self.flagged_ips,
            key=lambda ip: (self.ip_stats[ip]['threat_score'], self.ip_stats[ip]['count']),
            reverse=True
        )
        
        print(f"{Colors.BOLD}FLAGGED IPs (Sorted by Threat):{Colors.RESET}")
        print(f"{'─'*80}")
        
        for ip in sorted_ips[:20]:  # Show top 20
            stats = self.ip_stats[ip]
            display = self._format_ip_display(ip)
            
            print(f"{display}")
            print(f"  └─ Attacks: {stats['count']:3} | Ports: {', '.join(map(str, list(stats['ports'])[:3]))} | Score: {stats['threat_score']}%")
        
        if len(sorted_ips) > 20:
            print(f"\n{Colors.YELLOW}... and {len(sorted_ips) - 20} more flagged IPs{Colors.RESET}")
        
        print(f"\n{Colors.CYAN}Press Ctrl+C to stop monitoring{Colors.RESET}")
    
    def monitor_logs(self, update_interval: float = 2.0):
        """Monitor log files in real-time"""
        print(f"{Colors.GREEN}Starting real-time monitor...{Colors.RESET}")
        print(f"Log directory: {LOG_DIR}")
        print(f"Update interval: {update_interval}s")
        print(f"High threat threshold: {HIGH_THREAT_THRESHOLD}%\n")
        
        last_size = {}
        
        try:
            while True:
                # Find all log files
                log_files = list(LOG_DIR.glob("honeypot_*.jsonl"))
                
                for log_file in log_files:
                    try:
                        current_size = os.path.getsize(log_file)
                        
                        # Check if file has new data
                        if log_file not in last_size or current_size > last_size[log_file]:
                            with open(log_file, 'r') as f:
                                # Seek to last position if known
                                if log_file in last_size:
                                    f.seek(last_size[log_file])
                                
                                # Process new lines
                                for line in f:
                                    try:
                                        attack = json.loads(line.strip())
                                        self.process_attack(attack)
                                    except json.JSONDecodeError:
                                        continue
                            
                            last_size[log_file] = current_size
                    
                    except Exception as e:
                        continue
                
                # Update display
                self.display_dashboard()
                
                # Wait before next update
                time.sleep(update_interval)
        
        except KeyboardInterrupt:
            print(f"\n\n{Colors.GREEN}Monitoring stopped by user{Colors.RESET}")
            self.display_summary()
    
    def display_summary(self):
        """Display final summary"""
        print(f"\n{Colors.BOLD + Colors.CYAN}{'='*80}{Colors.RESET}")
        print(f"{Colors.BOLD}MONITORING SESSION SUMMARY{Colors.RESET}")
        print(f"{'='*80}")
        
        runtime = time.time() - self.start_time
        print(f"Runtime: {int(runtime)}s ({runtime/60:.1f} minutes)")
        print(f"Total attacks processed: {self.total_attacks}")
        print(f"Unique IPs: {len(self.ip_stats)}")
        print(f"Flagged IPs: {len(self.flagged_ips)}")
        
        if self.flagged_ips:
            print(f"\n{Colors.RED + Colors.BOLD}TOP 10 MOST DANGEROUS IPs:{Colors.RESET}")
            sorted_ips = sorted(
                self.flagged_ips,
                key=lambda ip: (self.ip_stats[ip]['threat_score'], self.ip_stats[ip]['count']),
                reverse=True
            )
            
            for i, ip in enumerate(sorted_ips[:10], 1):
                stats = self.ip_stats[ip]
                print(f"{i:2}. {ip:15} - Score: {stats['threat_score']:3}% | Attacks: {stats['count']:4} | {'BOT' if stats['is_bot'] else 'HUMAN'}")
        
        print(f"{'='*80}\n")


def main():
    import argparse
    
    parser = argparse.ArgumentParser(
        description='Real-time honeypot attack monitor with IP flagging',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  python realtime_monitor.py
  python realtime_monitor.py --interval 1
  python realtime_monitor.py --threshold 30
        '''
    )
    parser.add_argument('--interval', type=float, default=2.0,
                        help='Update interval in seconds (default: 2.0)')
    parser.add_argument('--threshold', type=int, default=HIGH_THREAT_THRESHOLD,
                        help=f'Threat score threshold for flagging (default: {HIGH_THREAT_THRESHOLD})')
    
    args = parser.parse_args()
    
    # Update threshold if specified
    global HIGH_THREAT_THRESHOLD
    HIGH_THREAT_THRESHOLD = args.threshold
    
    monitor = RealtimeMonitor()
    monitor.monitor_logs(update_interval=args.interval)


if __name__ == '__main__':
    main()
