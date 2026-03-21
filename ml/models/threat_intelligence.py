from datetime import datetime , timedelta
import requests
import os
import json
from pathlib import Path

DATA_DIR = Path("data")
DATA_DIR.mkdir(exist_ok=True)
THREAT_CACHE_FILE =  DATA_DIR / "threat_cache.json"




class ThreatIntelligence:
    def __init__(self, api_key):
        
        self.api_key = api_key
        self.cache_file = THREAT_CACHE_FILE
        self.cache = self.load_cache_from_disk()
        self.cache_loaded_at = datetime.now()

        print(f"[Init] Loaded {len(self.cache)} threat entries")

    def is_private_ip(self , ip):
        """Check if IP is private/reserved (skip API calls for these)"""
        
        if ip.startswith("10.") or ip.startswith("192.168.") or ip.startswith("127.") :
            return True
        if ip.startswith("172."):
            octets = ip.split(".")
            if len(octets) == 4 and 16 <= int(octets[1]) <= 31 :
                return True
        return False
    
    def load_cache_from_disk(self):
        """Load threat cache from disk """

        if not self.cache_file.exists():
            return {}
        try:
            with open(self.cache_file) as f:
                return json.load(f)
        except json.JSONDecodeError :
            print(f"[WARNING] JSON corrupt , starting fresh")
            return {}
        except PermissionError:
            print(f"[WARNING] Can't read file, starting fresh")
            return {}
        except Exception as e:
            print(f"[WARNING] Error {e}, starting fresh")
            return {}
    def save_cache_to_disk(self):
        """save in memory cache to disk"""

        try:
            self.cache_file.parent.mkdir(parents=True , exist_ok=True)

            with open(self.cache_file , 'w') as f:
                json.dump(self.cache , f , indent=2)
        except Exception as e:
            print(f"[WARINING] Failed to save: {e}")

    def is_cache_expired(self , ip ):
        """check if this IP's data older then 12h"""

        if ip not in self.cache:
            return True
        try:
            last_updated_str = self.cache[ip].get("last_updated")
            last_updated = datetime.fromisoformat(last_updated_str)
            age = datetime.now()  - last_updated

            return age > timedelta(hours=12)
        except:
            return True
    def handle_error(self , error , ip):
        """handle api error"""
        print(f"[ERROR] Lookup failed for {ip}: {error}")

        if ip in self.cache:
            data = self.cache[ip].copy()
            data["is_stale"] = True
            data["stale_reason"] = f"API down , using cached from {data.get('last_updated')}"
            return data
        else:
            return {
                "status": "error",
                "ip": ip,
                "error" : str(error),
                "is_stale" : True
            }
    def get_threat_data(self , ip):
        """Get threat data for an IP
        
        skips private IPs
        if not in cache or expired = fetch from api
        save to cache after api sucess and return data
        api error = either stale cache  or error"""

        if self.is_private_ip(ip):
            return{
                "status" : "private_ip",
                "ip": ip,
                "data": None
            }
        if ip in self.cache and not self.is_cache_expired(ip):
            print(f"[Cache hit] {ip}")
            return self.cache[ip]
        
        if not self.api_key : 
            print(f"[ERROR] No API key configured")
            return self.handle_error("No API key" , ip)
        
        print(f"[API call] fetching threat data for {ip}")

        try:
            
            url = "https://api.abuseipdb.com/api/v2/check"

            headers = {
                "key": self.api_key,
                "Accept" : "application/json"
            }

            params = {
                "ipAddress" : ip,
                "maxAgeInDays" : 90 
            }
            print(f"[API] Calling AbuseIPDB for {ip}")

            response =  requests.get(url , headers=headers , params=params , timeout=5)
            response.raise_for_status()

            api_response = response.json()

            if not api_response.get("data"):
                raise Exception("No data field in AbuseIPDB response")
            
            threat_data =  api_response["data"]

            self.cache[ip] = {
                "threat_data" : threat_data,
                "last_updated": datetime.now().isoformat(),
                "status" : "success"
            }

            self.save_cache_to_disk()

            score = threat_data.get("abuseConfidenceScore", 0)
            reports = threat_data.get("totalReports" , 0)
            print(f"[Success] {ip} - Score: {score}% | Reports: {reports}")

            return self.cache[ip]
        except requests.Timeout : 
            print(f"[TIMEOUT] AbuseIPDB API took too long (>5s) for {ip}")
            return self.handle_error("API timeout (>5 seconds)", ip)
        except requests.RequestException as e:
            print(f"[NETWORK ERROR] Failed to reach AbuseIPDB: {e}")
            return self.handle_error(f"Network error:{str(e)}" , ip)
        except json.JSONDecodeError :
            print(f"[JSON ERROR] AbuseIPDB response was not valid JSON for {ip}")
            return self.handle_error(f"Invalid JSON response from AbuseIPBD" , ip)
        except Exception as e:
            print(f"[ERROR] Unexpected error for: {ip}")
            return self.handle_error(str(e) , ip)
        
    def enrich_attack(self , attack):
        """
        adds threat intelligence data to record
        """

        source_ip = attack.get('source_ip')

        if not source_ip :
            return attack
        
        data = self.get_threat_data(source_ip)

        attack['threat_intelligence'] = data

        return attack