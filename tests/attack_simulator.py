#!/usr/bin/env python3
"""
Honeypot Attack Simulation Script
Simulates realistic attacks from different IP addresses for testing.
Can be run from attacker machine or locally with spoofed headers.
"""

import socket
import time
import random
import requests
import sys
from datetime import datetime
from typing import List, Tuple
from urllib.parse import urlencode

# Configuration
TARGET_HOST = "127.0.0.1"  # Change to honeypot IP
TARGET_PORT_SSH = 22
TARGET_PORT_FTP = 21
TARGET_PORT_TELNET = 23
TARGET_PORT_HTTP = 80

# Simulated attacking IPs (for X-Forwarded-For header)
ATTACKER_IPS = [
    "192.168.100.50",    # Local network
    "203.0.113.45",      # ISP range
    "198.51.100.200",    # Another ISP
    "45.142.120.50",     # Known botnet
    "195.154.173.208",   # European attacker
    "39.96.54.123",      # Asian attacker
    "185.220.101.1",     # Tor exit node
]

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
    def __init__(self, target_host, verbose=True):
        self.target_host = target_host
        self.verbose = verbose
        self.stats = {
            'ssh': 0,
            'ftp': 0,
            'telnet': 0,
            'http': 0,
            'total': 0
        }
    
    def log(self, message):
        if self.verbose:
            timestamp = datetime.now().strftime('%H:%M:%S')
            print(f"[{timestamp}] {message}")
    
    def simulate_ssh_attack(self, attacker_ip: str):
        """Simulate SSH brute force attempt"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            sock.connect((self.target_host, TARGET_PORT_SSH))
            
            # Read banner
            banner = sock.recv(1024).decode('utf-8', errors='ignore')
            self.log(f"[SSH] {attacker_ip} → Connected, received banner")
            
            # Try credentials
            username, password = random.choice(CREDENTIALS)
            sock.send(f"{username}\n".encode())
            time.sleep(0.5)
            sock.send(f"{password}\n".encode())
            
            self.log(f"[SSH] {attacker_ip} → Tried: {username}:{password}")
            self.stats['ssh'] += 1
            sock.close()
            
        except Exception as e:
            self.log(f"[SSH] {attacker_ip} → Error: {str(e)[:50]}")
    
    def simulate_ftp_attack(self, attacker_ip: str):
        """Simulate FTP login attempt"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            sock.connect((self.target_host, TARGET_PORT_FTP))
            
            # Read FTP banner
            banner = sock.recv(1024).decode('utf-8', errors='ignore')
            self.log(f"[FTP] {attacker_ip} → Connected")
            
            # Send USER command
            username, password = random.choice(CREDENTIALS)
            sock.send(f"USER {username}\r\n".encode())
            time.sleep(0.3)
            response = sock.recv(1024).decode('utf-8', errors='ignore')
            
            # Send PASS command
            sock.send(f"PASS {password}\r\n".encode())
            time.sleep(0.3)
            
            self.log(f"[FTP] {attacker_ip} → Tried: {username}:{password}")
            self.stats['ftp'] += 1
            sock.close()
            
        except Exception as e:
            self.log(f"[FTP] {attacker_ip} → Error: {str(e)[:50]}")
    
    def simulate_telnet_attack(self, attacker_ip: str):
        """Simulate Telnet login attempt"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            sock.connect((self.target_host, TARGET_PORT_TELNET))
            
            # Read Telnet banner
            data = sock.recv(1024)
            self.log(f"[TELNET] {attacker_ip} → Connected")
            
            # Try login
            username, password = random.choice(CREDENTIALS)
            sock.send(f"{username}\n".encode())
            time.sleep(0.3)
            sock.send(f"{password}\n".encode())
            time.sleep(0.3)
            
            # Try a command
            cmd = random.choice(COMMANDS)
            sock.send(f"{cmd}\n".encode())
            
            self.log(f"[TELNET] {attacker_ip} → Login + cmd: {cmd}")
            self.stats['telnet'] += 1
            sock.close()
            
        except Exception as e:
            self.log(f"[TELNET] {attacker_ip} → Error: {str(e)[:50]}")
    
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
            
            # Try different paths
            path = random.choice(HTTP_PATHS)
            url = f"http://{self.target_host}:{TARGET_PORT_HTTP}{path}"
            
            response = requests.get(url, headers=headers, timeout=2)
            self.log(f"[HTTP] {attacker_ip} → GET {path} ({response.status_code})")
            
            # Simulate credential submission
            if random.random() > 0.5:
                username, password = random.choice(CREDENTIALS)
                data = {
                    'username': username,
                    'password': password,
                    'login': 'Login'
                }
                response = requests.post(
                    f"http://{self.target_host}:{TARGET_PORT_HTTP}/login",
                    headers=headers,
                    data=data,
                    timeout=2
                )
                self.log(f"[HTTP] {attacker_ip} → POST /login ({username}:{password})")
            
            self.stats['http'] += 1
            
        except Exception as e:
            self.log(f"[HTTP] {attacker_ip} → Error: {str(e)[:50]}")
    
    def run_full_attack_sequence(self, attacker_ip: str):
        """Run multiple attack types from single IP"""
        self.log(f"{'='*60}")
        self.log(f"STARTING ATTACK SEQUENCE FROM: {attacker_ip}")
        self.log(f"{'='*60}")
        
        # Simulate different attacks
        self.simulate_http_attack(attacker_ip)
        time.sleep(random.uniform(0.5, 2))
        
        self.simulate_ftp_attack(attacker_ip)
        time.sleep(random.uniform(0.5, 2))
        
        self.simulate_telnet_attack(attacker_ip)
        time.sleep(random.uniform(0.5, 2))
        
        self.simulate_ssh_attack(attacker_ip)
        time.sleep(random.uniform(0.5, 2))
        
        self.stats['total'] += 4
    
    def run_distributed_attack(self, num_attackers: int = 5):
        """Simulate attacks from multiple IPs"""
        print("\n" + "="*70)
        print("HONEYPOT DISTRIBUTED ATTACK SIMULATION")
        print("="*70)
        print(f"Target: {self.target_host}")
        print(f"Simulating {num_attackers} attackers")
        print("="*70 + "\n")
        
        attackers = random.sample(ATTACKER_IPS, min(num_attackers, len(ATTACKER_IPS)))
        
        try:
            for i, attacker_ip in enumerate(attackers, 1):
                print(f"\n[{i}/{num_attackers}] Attacker: {attacker_ip}")
                self.run_full_attack_sequence(attacker_ip)
                
                if i < num_attackers:
                    delay = random.uniform(3, 8)
                    print(f"\nWaiting {delay:.1f}s before next attack...\n")
                    time.sleep(delay)
        
        except KeyboardInterrupt:
            print("\n\n[!] Attack simulation stopped by user")
        
        finally:
            self.print_stats()
    
    def print_stats(self):
        """Print attack statistics"""
        print("\n" + "="*70)
        print("ATTACK SUMMARY")
        print("="*70)
        print(f"SSH attempts:    {self.stats['ssh']}")
        print(f"FTP attempts:    {self.stats['ftp']}")
        print(f"TELNET attempts: {self.stats['telnet']}")
        print(f"HTTP attempts:   {self.stats['http']}")
        print(f"TOTAL:           {self.stats['total']}")
        print("="*70)
        print("\nCheck dashboard at http://localhost:5000")
        print("All attacks should appear with threat intelligence enrichment!")

def main():
    import argparse
    
    parser = argparse.ArgumentParser(description='Honeypot Attack Simulator')
    parser.add_argument('--target', default='127.0.0.1', help='Target honeypot IP')
    parser.add_argument('--num-attackers', type=int, default=5, help='Number of simulated attackers')
    parser.add_argument('--verbose', action='store_true', default=True, help='Verbose output')
    
    args = parser.parse_args()
    
    simulator = AttackSimulator(args.target, verbose=args.verbose)
    simulator.run_distributed_attack(args.num_attackers)

if __name__ == '__main__':
    main()
