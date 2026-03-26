#!/usr/bin/env python3
"""
Honeypot Attack Simulation Script
Simulates realistic attacks from different IP addresses for testing.
Can be run from attacker machine or locally with spoofed headers.
"""

import os
import socket
import time
import random
import requests
from datetime import datetime
from typing import List, Dict, Tuple
from contextlib import contextmanager
from concurrent.futures import ThreadPoolExecutor, as_completed

# Configuration
TARGET_HOST = os.getenv("TARGET_HOST", "192.168.100.200")  # Use env var or fallback
PORTS = {
    'ssh': 22,
    'ftp': 21,
    'telnet': 23,
    'http': 80
}
DEFAULT_TIMEOUT = 5  # Increased to allow SSH/FTP/Telnet handshakes to complete
MAX_CYCLES = 100
MAX_PARALLEL_ATTACKS = 10  # For threaded mode

# Known malicious IPs from AbuseIPDB and threat feeds
FLAGGED_IPS = [
    "150.5.169.176",
    "2.57.122.199",
    "36.110.172.218",
    "77.83.206.248",
    "103.80.87.208",
    "34.126.197.2",
    "197.199.224.52",
    "61.151.249.194",
    "89.207.250.145",
    "162.241.203.162",
    "45.148.10.147",
    "80.94.95.115",
    "2.57.122.194",
    "103.187.165.26",
    "174.138.78.232",
    "162.120.6.20",
    "182.150.115.56",
    "74.7.243.229",
    "187.251.123.104",
    "61.72.55.130",
    "2.57.121.69",
    "152.32.185.214",
    "213.209.159.159",
    "195.178.110.15",
    "109.75.161.93",
    "45.148.10.157",
    "139.59.169.42",
    "103.63.25.61",
    "3.143.162.210",
    "52.187.249.150",
    "43.245.97.82",
    "36.255.223.75",
    "103.20.122.54",
    "2.57.121.86",
    "163.192.24.247",
    "45.227.254.170",
    "181.191.128.18",
    "66.132.172.119",
    "176.120.22.13",
    "45.195.221.26",
    "31.141.204.118",
    "2.57.122.189",
    "45.78.202.217",
    "98.71.8.129",
    "178.128.214.41",
    "66.132.172.253",
    "116.111.2.94",
    "176.120.22.17",
    "171.25.158.73",
    "103.18.14.109",
    "85.203.21.132",
    "118.193.61.170",
    "174.134.45.64",
    "209.141.41.212",
    "222.255.214.79",
    "80.94.95.116",
    "92.118.39.87",
    "172.94.9.205",
    "220.247.223.56",
    "195.158.4.216",
]

def generate_random_ip() -> str:
    """Generate realistic public IP addresses (avoiding private ranges)"""
    # Exclude: 10.x, 172.16-31.x, 192.168.x, 127.x, 0.x, 255.x
    valid_ranges = [range(1, 10), range(11, 127), range(128, 172), 
                    range(173, 192), range(193, 223)]
    first = random.choice(random.choice(valid_ranges))
    return f"{first}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"

def is_private_ip(ip: str) -> bool:
    """Check if IP is private/reserved"""
    if ip.startswith(("10.", "127.", "192.168.", "172.")):
        if ip.startswith("172."):
            octets = ip.split(".")
            if len(octets) == 4 and 16 <= int(octets[1]) <= 31:
                return True
    return any(ip.startswith(prefix) for prefix in ("10.", "127.", "192.168."))

# Pre-generate large pool of unique attacker IPs (filter out any private ones)
RANDOM_IPS = [ip for ip in set(generate_random_ip() for _ in range(600)) if not is_private_ip(ip)]
FLAGGED_IPS_CLEAN = [ip for ip in FLAGGED_IPS if not is_private_ip(ip)]
ATTACKER_IPS = FLAGGED_IPS_CLEAN + RANDOM_IPS  # Blend flagged + random (public IPs only)

# Credentials to try
CREDENTIALS = [
    ("admin", "admin"),
    ("root", "password"),
    ("root", "toor"),
    ("admin", "12345"),
    ("user", "password"),
    ("test", "test"),
    ("pi", "raspberry"),
    ("oracle", "oracle"),
]

# Commands to execute after login
COMMANDS = [
    "whoami",
    "id",
    "pwd",
    "ls -la",
    "cat /etc/passwd",
    "uname -a",
    "netstat -an",
    "ps aux",
]

# HTTP paths to probe
HTTP_PATHS = [
    "/",
    "/admin",
    "/login",
    "/api",
    "/config",
    "/.git",
    "/wp-admin",
]

class AttackSimulator:
    """Simulates various network attacks against a honeypot"""
    
    def __init__(self, target_host: str, verbose: bool = True):
        self.target_host = target_host
        self.verbose = verbose
        self.stats = {service: 0 for service in PORTS.keys()}
        self.stats['total'] = 0
    
    def log(self, message: str):
        """Log message with timestamp if verbose mode enabled"""
        if self.verbose:
            print(f"[{datetime.now().strftime('%H:%M:%S')}] {message}")
    
    @contextmanager
    def create_socket(self, port: int):
        """Context manager for socket connections with timeout"""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(DEFAULT_TIMEOUT)
        try:
            sock.connect((self.target_host, port))
            yield sock
        finally:
            sock.close()
    
    def simulate_ssh_attack(self, attacker_ip: str):
        """Simulate SSH brute force attempt"""
        try:
            with self.create_socket(PORTS['ssh']) as sock:
                sock.recv(1024)  # Banner
                username, password = random.choice(CREDENTIALS)
                sock.send(f"{username}\n{password}\n".encode())
                self.stats['ssh'] += 1
                if self.verbose:
                    self.log(f"[SSH] {attacker_ip} - {username}:{password}")
        except Exception:
            pass  # Silent failure for speed
    
    def simulate_ftp_attack(self, attacker_ip: str):
        """Simulate FTP login attempt"""
        try:
            with self.create_socket(PORTS['ftp']) as sock:
                sock.recv(1024)  # Banner
                username, password = random.choice(CREDENTIALS)
                sock.send(f"USER {username}\r\nPASS {password}\r\n".encode())
                self.stats['ftp'] += 1
                if self.verbose:
                    self.log(f"[FTP] {attacker_ip} - {username}:{password}")
        except Exception:
            pass
    
    def simulate_telnet_attack(self, attacker_ip: str):
        """Simulate Telnet login attempt"""
        try:
            with self.create_socket(PORTS['telnet']) as sock:
                sock.recv(1024)  # Banner
                username, password = random.choice(CREDENTIALS)
                cmd = random.choice(COMMANDS)
                sock.send(f"{username}\n{password}\n{cmd}\n".encode())
                self.stats['telnet'] += 1
                if self.verbose:
                    self.log(f"[TELNET] {attacker_ip} - {cmd}")
        except Exception:
            pass
    
    def simulate_http_attack(self, attacker_ip: str):
        """Simulate HTTP reconnaissance and credential submission"""
        try:
            headers = {
                'X-Forwarded-For': attacker_ip,
                'User-Agent': random.choice([
                    'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
                    'curl/7.68.0',
                    'python-requests/2.28.0',
                ])
            }
            
            path = random.choice(HTTP_PATHS)
            url = f"http://{self.target_host}:{PORTS['http']}{path}"
            requests.get(url, headers=headers, timeout=DEFAULT_TIMEOUT)
            
            # 50% chance to submit credentials
            if random.random() > 0.5:
                username, password = random.choice(CREDENTIALS)
                requests.post(
                    f"http://{self.target_host}:{PORTS['http']}/login",
                    headers=headers,
                    data={'username': username, 'password': password, 'login': 'Login'},
                    timeout=DEFAULT_TIMEOUT
                )
                if self.verbose:
                    self.log(f"[HTTP] {attacker_ip} - {path} + login")
            
            self.stats['http'] += 1
        except Exception:
            pass
    
    def simulate_random_port_attack(self, attacker_ip: str):
        """Simulate attack on random port"""
        attack_methods = {
            'ssh': self.simulate_ssh_attack,
            'ftp': self.simulate_ftp_attack,
            'telnet': self.simulate_telnet_attack,
            'http': self.simulate_http_attack
        }
        method = random.choice(list(attack_methods.values()))
        method(attacker_ip)
    
    def run_chaotic_attack_sequence(self, attacker_ip: str, num_attacks: int = None):
        """Simulate realistic chaotic attack - random ports, minimal delays"""
        if num_attacks is None:
            num_attacks = random.randint(3, 8)
            
        for _ in range(num_attacks):
            self.simulate_random_port_attack(attacker_ip)
            time.sleep(random.uniform(0.3, 1.0))  # Faster
        
        self.stats['total'] += num_attacks
    
    def run_distributed_attack(self, num_attackers: int = 5, threaded: bool = False):
        """Simulate realistic distributed attacks with varied strategies"""
        if self.verbose:
            print("\n" + "="*70)
            print("🚨 LE-TRAP HONEYPOT: LIVE ATTACK SIMULATION 🚨")
            print("="*70)
            print(f"Target: {self.target_host}")
            print(f"Attacking IPs: {num_attackers} | Mode: {'⚡ THREADED (MASSIVE)' if threaded else 'SEQUENTIAL'}")
            print(f"Unique IPs (including {len(FLAGGED_IPS)} BLACKLISTED): {len(ATTACKER_IPS)}")
            print("="*70 + "\n")
        
        attackers = random.sample(ATTACKER_IPS, min(num_attackers, len(ATTACKER_IPS)))
        strategies = [
            ('RAPID BOT', 0.4, lambda ip: self._rapid_bot_attack(ip)),
            ('PORT SCANNING', 0.3, lambda ip: self.run_chaotic_attack_sequence(ip)),
            ('SLOW RECON', 0.3, lambda ip: self._slow_recon_attack(ip))
        ]
        
        try:
            if threaded:
                self._run_threaded_attacks(attackers, strategies)
            else:
                self._run_sequential_attacks(attackers, strategies)
        except KeyboardInterrupt:
            if self.verbose:
                print("\n\n[!] Simulation stopped by user")
        finally:
            if self.verbose:
                self.print_stats()
            else:
                print(f"\n✅ COMPLETED: {self.stats['total']} attacks from {num_attackers} IPs")
                print(f"📊 Check dashboard: http://localhost:5000")
                print(f"🚨 {len(FLAGGED_IPS)} DANGEROUS IPs INCLUDED IN ATTACK")
    
    def _run_sequential_attacks(self, attackers, strategies):
        """Run attacks sequentially with minimal delays"""
        for i, attacker_ip in enumerate(attackers, 1):
            if self.verbose and (i % 25 == 0 or i == 1):
                print(f"\n[{i}/{len(attackers)}] {attacker_ip}")
            
            strategy_name, _, strategy_func = random.choices(
                strategies, 
                weights=[s[1] for s in strategies]
            )[0]
            
            strategy_func(attacker_ip)
            
            # Progress indicator for non-verbose mode
            if not self.verbose and i % 10 == 0:
                print(f"Progress: {i}/{len(attackers)} attackers", end='\r')
            
            # Minimal delay between attackers
            if i % 10 == 0 and i < len(attackers):
                time.sleep(random.uniform(1, 3))
    
    def _run_threaded_attacks(self, attackers, strategies):
        """Run attacks in parallel using thread pool - ULTRA FAST FOR VIDEO"""
        def attack_worker(attacker_ip, idx):
            # Cycle through ports: IP0→FTP, IP1→SSH, IP2→Telnet, IP3→HTTP, IP4→FTP, etc.
            port_order = [
                self.simulate_ftp_attack,
                self.simulate_ssh_attack,
                self.simulate_telnet_attack,
                self.simulate_http_attack
            ]
            # Run the port in order, then add a few random ones
            port_order[idx % 4](attacker_ip)
            self.stats['total'] += 1
            
            # 50% chance to do extra attacks
            if random.random() > 0.5:
                strategy_name, _, strategy_func = random.choices(
                    strategies,
                    weights=[s[1] for s in strategies]
                )[0]
                strategy_func(attacker_ip)
            return attacker_ip
        
        # 50 workers for MASSIVE concurrent attacks (video impact!)
        with ThreadPoolExecutor(max_workers=50) as executor:
            futures = [executor.submit(attack_worker, ip, idx) for idx, ip in enumerate(attackers)]
            completed = 0
            
            for future in as_completed(futures):
                completed += 1
                if not self.verbose and completed % 25 == 0:
                    print(f"🚨 {completed}/{len(attackers)} attacking simultaneously", end='\r')
                elif self.verbose and completed % 25 == 0:
                    print(f"🚨 {completed}/{len(attackers)} attacking simultaneously")
    
    def _rapid_bot_attack(self, attacker_ip: str):
        """RAPID bot attack pattern - hits each port sequentially ULTRA FAST FOR VIDEO"""
        port_cycle = [
            self.simulate_ftp_attack,
            self.simulate_ssh_attack,
            self.simulate_telnet_attack,
            self.simulate_http_attack
        ]
        count = random.randint(12, 20)  # Way more attacks
        for i in range(count):
            port_cycle[i % 4](attacker_ip)  # Cycle through all 4 ports
            time.sleep(random.uniform(0.1, 0.3))  # ULTRA FAST
        self.stats['total'] += count
    
    def _slow_recon_attack(self, attacker_ip: str):
        """Slow reconnaissance attack pattern"""
        count = random.randint(3, 5)
        for _ in range(count):
            self.simulate_random_port_attack(attacker_ip)
            time.sleep(random.uniform(2, 5))  # Still realistic but faster
        self.stats['total'] += count
    
    def print_stats(self):
        """Print attack statistics summary"""
        print("\n" + "="*70)
        print("ATTACK SUMMARY")
        print("="*70)
        for service in ['ssh', 'ftp', 'telnet', 'http']:
            print(f"{service.upper():8} attempts: {self.stats[service]:4}")
        print(f"{'TOTAL':8}          : {self.stats['total']:4}")
        print("="*70)
        print("\nDashboard: http://localhost:5000")
        print("Attacks logged with threat intelligence enrichment")

def main():
    """Main entry point for attack simulator"""
    import argparse
    
    parser = argparse.ArgumentParser(
        description='LE-Trap Honeypot Attack Simulator',
        usage='python attack_simulator.py NUM_ATTACKERS'
    )
    parser.add_argument('num_attackers', type=int, nargs='?', default=10,
                        help='Number of attackers to simulate (default: 10)')
    
    args = parser.parse_args()
    
    print(f"🚀 Launching {args.num_attackers} attacks...")
    
    simulator = AttackSimulator(TARGET_HOST, verbose=False)
    simulator.run_distributed_attack(args.num_attackers, threaded=True)
    
    print(f"✅ Complete | Dashboard: http://localhost:5000")

if __name__ == '__main__':
    main()
