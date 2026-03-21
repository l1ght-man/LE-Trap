#!/bin/bash
# ============================================================================
# Honeypot Attack Simulation Script (Run from Kali WSL)
# ============================================================================
# Tests all honeypot ports and simulates real-world attacks
#
# USAGE:
#   chmod +x test_honeypot.sh
#   ./test_honeypot.sh <target_ip>
#
# Example:
#   ./test_honeypot.sh 172.20.208.1    (WSL to Windows)
#   ./test_honeypot.sh 192.168.1.100   (Different machine)
# ============================================================================

set -e

TARGET=${1:-"172.20.208.1"}  # Default to typical WSL->Windows IP
PORT_SSH=22
PORT_FTP=21
PORT_TELNET=23
PORT_HTTP=80

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}╔════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║     HoneyPot Attack Simulation Test Suite         ║${NC}"
echo -e "${BLUE}╔════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}Target: ${TARGET}${NC}\n"

# ============================================================================
# Test 1: HTTP Port 80 - Fake Login Page with X-Forwarded-For
# ============================================================================
test_http() {
    echo -e "\n${YELLOW}[TEST 1]${NC} Testing HTTP Port (80) with spoofed IPs..."
    
    # Array of fake IPs to simulate
    FAKE_IPS=("8.8.8.8" "185.220.101.1" "45.142.120.50")
    
    for fake_ip in "${FAKE_IPS[@]}"; do
        echo -e "${BLUE}→${NC} Sending request from spoofed IP: ${fake_ip}"
        
        # Simple GET request with X-Forwarded-For
        curl -s -H "X-Forwarded-For: ${fake_ip}" "http://${TARGET}:${PORT_HTTP}/" > /dev/null && \
            echo -e "${GREEN}✓${NC} GET request sent from ${fake_ip}"
        
        sleep 0.2
    done
    
    # Fake credential submissions from different IPs
    echo -e "${BLUE}→${NC} Submitting credentials from 39.96.54.123 (China)..."
    curl -s -H "X-Forwarded-For: 39.96.54.123" -X POST "http://${TARGET}:${PORT_HTTP}/login" \
        -d "username=hacker&password=123456" > /dev/null
    
    echo -e "${BLUE}→${NC} Submitting credentials from 195.154.173.208 (France)..."
    curl -s -H "X-Forwarded-For: 195.154.173.208" "http://${TARGET}:${PORT_HTTP}/admin?username=attacker&password=letmein" > /dev/null
    
    echo -e "${GREEN}✓${NC} HTTP tests completed from 5 different countries"
}

# ============================================================================
# Test 2: FTP Port 21
# ============================================================================
test_ftp() {
    echo -e "\n${YELLOW}[TEST 2]${NC} Testing FTP Port (21)..."
    
    echo -e "${BLUE}→${NC} Attempting FTP connection..."
    timeout 5 nc -v ${TARGET} ${PORT_FTP} <<EOF 2>&1 | head -n 5
USER anonymous
PASS guest
QUIT
EOF
    echo -e "${GREEN}✓${NC} FTP connection attempted"
}

# ============================================================================
# Test 3: Telnet Port 23 - Multiple Login Attempts
# ============================================================================
test_telnet() {
    echo -e "\n${YELLOW}[TEST 3]${NC} Testing Telnet Port (23)..."
    
    # Failed login attempt
    echo -e "${BLUE}→${NC} Attempting failed login (hacker/password123)..."
    (
        sleep 0.3
        echo "hacker"
        sleep 0.3
        echo "password123"
        sleep 0.5
    ) | timeout 10 telnet ${TARGET} ${PORT_TELNET} 2>&1 | grep -i "login\|incorrect\|welcome" || true
    
    sleep 0.5
    
    # Successful login with valid credentials
    echo -e "${BLUE}→${NC} Attempting successful login (admin/admin)..."
    (
        sleep 0.3
        echo "admin"
        sleep 0.3
        echo "admin"
        sleep 0.5
        echo "whoami"
        sleep 0.2
        echo "ls -la"
        sleep 0.2
        echo "cat /etc/passwd"
        sleep 0.2
        echo "exit"
        sleep 0.2
    ) | timeout 15 telnet ${TARGET} ${PORT_TELNET} 2>&1 | grep -i "login\|welcome\|root\|bash" || true
    
    echo -e "${GREEN}✓${NC} Telnet attacks completed"
}

# ============================================================================
# Test 4: SSH Port 22 - Brute Force Simulation
# ============================================================================
test_ssh() {
    echo -e "\n${YELLOW}[TEST 4]${NC} Testing SSH Port (22)..."
    
    # Common username/password combinations
    credentials=(
        "root:toor"
        "admin:admin"
        "user:userpass"
        "test:test123"
    )
    
    for cred in "${credentials[@]}"; do
        IFS=':' read -r user pass <<< "$cred"
        echo -e "${BLUE}→${NC} Trying SSH: ${user}/${pass}..."
        
        sshpass -p "${pass}" ssh -o StrictHostKeyChecking=no \
            -o UserKnownHostsFile=/dev/null \
            -o ConnectTimeout=5 \
            ${user}@${TARGET} -p ${PORT_SSH} \
            "whoami; ls -la; exit" 2>&1 | head -n 3 || true
        
        sleep 0.5
    done
    
    echo -e "${GREEN}✓${NC} SSH brute force simulation completed"
}

# ============================================================================
# Test 5: Port Scanning Simulation
# ============================================================================
test_port_scan() {
    echo -e "\n${YELLOW}[TEST 5]${NC} Simulating Port Scan..."
    
    echo -e "${BLUE}→${NC} Scanning common ports..."
    nmap -Pn -p 21,22,23,80,443,3306,8080 ${TARGET} 2>&1 | grep "open\|closed\|filtered" || true
    
    echo -e "${GREEN}✓${NC} Port scan completed"
}

# ============================================================================
# Main Execution
# ============================================================================

echo -e "\n${BLUE}Starting attack simulation in 1 second...${NC}"
sleep 1

# Check if required tools are installed
command -v curl >/dev/null 2>&1 || { echo -e "${RED}✗ curl not installed${NC}"; exit 1; }
command -v nc >/dev/null 2>&1 || { echo -e "${RED}✗ netcat not installed${NC}"; exit 1; }
command -v telnet >/dev/null 2>&1 || { echo -e "${RED}✗ telnet not installed${NC}"; exit 1; }
command -v sshpass >/dev/null 2>&1 || { echo -e "${RED}✗ sshpass not installed (run: sudo apt install sshpass)${NC}"; exit 1; }
command -v nmap >/dev/null 2>&1 || { echo -e "${RED}✗ nmap not installed${NC}"; exit 1; }

# Run all tests
test_http
test_ftp
test_telnet
test_ssh
test_port_scan

# ============================================================================
# Summary
# ============================================================================
echo -e "\n${BLUE}╔════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║              Test Suite Complete!                  ║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════════════════╝${NC}"
echo -e "\n${GREEN}✓${NC} All attacks simulated successfully!"
echo -e "\n${YELLOW}Next Steps:${NC}"
echo -e "  1. Check dashboard at http://${TARGET}:5000"
echo -e "  2. Verify logs in ./logs/ directory"
echo -e "  3. Test CSV/PDF export from dashboard"
echo -e "\n${BLUE}Expected Results:${NC}"
echo -e "  • HTTP: 5 events from different countries (USA, Russia, China, etc.)"
echo -e "  • FTP: 1 connection event"
echo -e "  • Telnet: 2 login attempts + commands"
echo -e "  • SSH: 4 login attempts (1 successful)"
echo -e "  • Total: ~12+ logged events"
echo -e "\n${YELLOW}Map Testing:${NC}"
echo -e "  • HTTP attacks should show up from 5 different countries"
echo -e "  • Real-time updates visible on dashboard"
echo ""
