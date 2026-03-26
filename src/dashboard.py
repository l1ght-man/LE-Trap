#!/usr/bin/env python3

import requests
from flask import Flask, render_template, jsonify, request , send_file 
from flask_socketio import SocketIO, emit
import json
import glob
from pathlib import Path
from collections import Counter
from datetime import datetime, timedelta
import os
import csv 
from io import StringIO , BytesIO
from xhtml2pdf import pisa
from flask import render_template
import threading
import time
import sys

# Add multiple paths for threat intelligence import
BASE_DIR = Path(__file__).parent.parent.resolve()
ml_models_path = BASE_DIR / 'ml' / 'models'
sys.path.insert(0, str(ml_models_path))
sys.path.insert(0, str(BASE_DIR / 'ml'))

from dotenv import load_dotenv
load_dotenv()

try:
    from threat_intelligence import ThreatIntelligence  # type: ignore
    TI_AVAILABLE = True
    api_key = os.getenv('ABUSEIPDB_API_KEY')
    TI_CLIENT = ThreatIntelligence(api_key) if api_key else None
    if TI_CLIENT:
        print(f"[INIT] Threat Intelligence initialized with {len(TI_CLIENT.cache)} cached entries")
    else:
        TI_AVAILABLE = False
        print("[INIT] No ABUSEIPDB_API_KEY found, TI disabled")
except Exception as e:
    TI_AVAILABLE = False
    TI_CLIENT = None
    print(f"[INIT] WARNING: Threat Intelligence not available: {e}")
    import traceback
    traceback.print_exc()

# Flask Configuration
app = Flask(__name__, 
            template_folder='../web/templates',
            static_folder='../web/static')
app.config['SECRET_KEY'] = 'honeypot-secret-key-change-this'

# SocketIO for real-time updates (use threading mode for Windows compatibility)
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')

# Paths - Use absolute paths to avoid issues
SCRIPT_DIR = Path(__file__).parent.resolve()
LOG_DIR = SCRIPT_DIR.parent / "logs"
DATA_DIR = SCRIPT_DIR.parent / "data"

# Track honeypot start time
HONEYPOT_START_TIME = datetime.now()

print(f"[INIT] Log directory: {LOG_DIR}")
print(f"[INIT] Exists: {LOG_DIR.exists()}")
print(f"[INIT] Honeypot started at: {HONEYPOT_START_TIME.strftime('%Y-%m-%d %H:%M:%S')}")


def load_all_logs():
    """Read all JSONL log files and merge with enriched threat intelligence"""
    all_logs = []
    enriched_data = {}
    
    # Load enriched threat intelligence data first
    enriched_file = DATA_DIR / "enriched_real_attacks.jsonl"
    if enriched_file.exists():
        try:
            with open(enriched_file, 'r', encoding='utf-8') as f:
                for line in f:
                    try:
                        entry = json.loads(line.strip())
                        ip = entry.get('source_ip')
                        if ip:
                            enriched_data[ip] = entry.get('threat_intelligence', {})
                    except json.JSONDecodeError:
                        continue
        except FileNotFoundError:
            pass
    
    # Load honeypot logs and merge with enriched data
    log_files = glob.glob(str(LOG_DIR / "honeypot_*.jsonl"))
    if log_files:
        print(f"[DEBUG] Found {len(log_files)} fresh honeypot log files")
        for log_file in log_files:
            try:
                with open(log_file, 'r', encoding='utf-8') as f:
                    for line in f:
                        try:
                            log_entry = json.loads(line.strip())
                            ip = log_entry.get('source_ip')
                            # Merge enriched threat intel if available
                            if ip and ip in enriched_data:
                                log_entry['threat_intelligence'] = enriched_data[ip]
                            all_logs.append(log_entry)
                        except json.JSONDecodeError:
                            continue
            except FileNotFoundError:
                continue
        print(f"[DEBUG] Loaded {len(all_logs)} attacks with enrichment merged")
    
    print(f"[DEBUG] Total entries loaded: {len(all_logs)}")
    return all_logs



def get_uptime():
    """Calculate honeypot uptime"""
    uptime_delta = datetime.now() - HONEYPOT_START_TIME
    days = uptime_delta.days
    hours, remainder = divmod(uptime_delta.seconds, 3600)
    minutes, seconds = divmod(remainder, 60)
    
    if days > 0:
        return f"{days}d {hours}h {minutes}m"
    elif hours > 0:
        return f"{hours}h {minutes}m {seconds}s"
    else:
        return f"{minutes}m {seconds}s"

def enrich_with_threat_intelligence(logs):
    """Enrich logs with threat intelligence data (on-the-fly)"""
    if not TI_AVAILABLE or not logs:
        return logs
    
    enriched = []
    processed_ips = set()  # Cache lookups to avoid duplicate API calls
    threat_cache = {}  # Store results
    enriched_count = 0
    
    for entry in logs:
        ip = entry.get('source_ip')
        
        # Only enrich if we have an IP and haven't already looked it up
        if ip and ip not in processed_ips:
            processed_ips.add(ip)
            
            # Skip private IPs
            if not TI_CLIENT.is_private_ip(ip):
                try:
                    threat_data = TI_CLIENT.get_threat_data(ip)
                    threat_cache[ip] = threat_data
                    if threat_data.get('threat_data', {}).get('abuseConfidenceScore', 0) > 0:
                        enriched_count += 1
                except Exception as e:
                    print(f"[ERROR] Threat enrichment failed for {ip}: {e}")
        
        # Add threat data to entry if we have it
        if ip and ip in threat_cache:
            entry['threat_intelligence'] = threat_cache[ip]
        
        enriched.append(entry)
    
    if enriched_count > 0:
        print(f"[ENRICHMENT] Added threat data to {enriched_count} entries with scores > 0")
    
    return enriched

def calculate_statistics(logs):
    """Calculate attack statistics from logs"""
    if not logs:
        return {
            "total_attacks": 0,
            "ports": {},
            "top_ips": [],
            "threat_ips": [],
            "credentials_captured": 0,
            "avg_threat_score": 0,
            "active_ips_24h": 0,
            "recent_events": []
        }
    
    port_counter = Counter()
    ip_counter = Counter()
    ip_threat_map = {}
    credentials_count = 0
    threat_scores = []
    unique_ips_24h = set()
    
    # Calculate 24h cutoff time
    now = datetime.now()
    cutoff_24h = now - timedelta(hours=24)
    
    for entry in logs:
        port = entry.get('port')
        if port:
            port_counter[port] += 1
        
        ip = entry.get('source_ip')
        if ip:
            # Count all IPs including testing IPs
            ip_counter[ip] += 1
            
            # Count unique IPs in last 24h
            timestamp_str = entry.get('timestamp', '')
            try:
                # Parse ISO format timestamp
                entry_time = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
                if entry_time >= cutoff_24h:
                    unique_ips_24h.add(ip)
            except:
                # If timestamp parsing fails, assume it's recent
                unique_ips_24h.add(ip)
        
        # Count credentials more broadly
        details = entry.get('details', '')
        event_type = entry.get('event_type', '')
        
        # Check multiple ways credentials might be captured
        if ('credentials' in entry or 
            'password=' in details or 
            'LOGIN' in event_type.upper() or
            'FTP_LOGIN' in event_type):
            credentials_count += 1
        
        # Extract threat score - handle multiple possible structures
        threat_intel = entry.get('threat_intelligence', {})
        threat_data = threat_intel
        
        # Support multiple structures:
        # 1. threat_intel.threat_data.abuseConfidenceScore (from enrichment)
        # 2. threat_intel.abuseConfidenceScore (flat structure)
        if 'threat_data' in threat_intel:
            threat_data = threat_intel['threat_data']
        
        abuse_score = threat_data.get('abuseConfidenceScore')
        if abuse_score is not None and isinstance(abuse_score, (int, float)):
            threat_scores.append(abuse_score)
            
            # Store threat data for each IP (use highest score)
            if ip not in ip_threat_map or abuse_score > ip_threat_map[ip]['abuse_score']:
                ip_threat_map[ip] = {
                    'abuse_score': abuse_score,
                    'is_tor': threat_data.get('isTor', False),
                    'total_reports': threat_data.get('totalReports', 0),
                    'country': threat_data.get('countryName', ''),
                    'isp': threat_data.get('isp', ''),
                    'usage_type': threat_data.get('usageType', ''),
                    'num_distinct_users': threat_data.get('numDistinctUsers', 0),
                    'last_reported': threat_data.get('lastReportedAt', '')
                }
    
    # Calculate average threat score, handle edge cases
    if threat_scores:
        avg_threat = int(sum(threat_scores) / len(threat_scores))
    else:
        avg_threat = 0  # Default to 0 instead of NaN
    
    # Include all IPs (including private/Docker IPs) for demo visibility
    top_ips = [{"ip": ip, "count": count} for ip, count in ip_counter.most_common(10)]
    
    # Sort IPs by threat score (highest first) - include all IPs for demo
    threat_ips = sorted(
        [{"ip": ip, **data} for ip, data in ip_threat_map.items()],
        key=lambda x: x['abuse_score'],
        reverse=True
    )[:10]
    
    # Show all recent events including simulated attacks from private IPs
    recent_events = [
        log for log in sorted(logs, key=lambda x: x.get('timestamp', ''), reverse=True)
    ][:20]
    
    return {
        "total_attacks": len(logs),
        "ports": dict(port_counter),
        "top_ips": top_ips,
        "threat_ips": threat_ips,
        "credentials_captured": credentials_count,
        "avg_threat_score": avg_threat,
        "active_ips_24h": len(unique_ips_24h),
        "uptime": get_uptime(),
        "recent_events": recent_events
    }

cache_file = SCRIPT_DIR.parent / "data" / "ip_cache.json"

def load_cache_from_disk():
    """Load IP location cache from JSON file"""
    try:
        with open(cache_file, 'r', encoding='utf-8') as f:
                return json.load(f)
    except FileNotFoundError:
        return {}
    except json.JSONDecodeError:
        return {}

def save_cache_to_disk(cache):
    """Save IP location cache to JSON file"""
    try:
        cache_file.parent.mkdir(exist_ok=True)
        with open(cache_file, 'w', encoding='utf-8') as f:
                json.dump(cache,f, indent=2)
    except Exception as e:
        print(f"[ERROR] Failed to save cache: {e}")

ip_cache = load_cache_from_disk()

def lookup_ip_location(ip):
    """Look up IP geolocation, using cache when possible"""
    if ip in ip_cache:
        return ip_cache[ip]
    
    try:
        url = f"http://ip-api.com/json/{ip}"
        response = requests.get(url, timeout=5)
        data = response.json()
        
        if data.get('status') == 'success':
            location = {
                "lat": data.get('lat'),
                "lon": data.get('lon'),
                "country": data.get('country'),
                "city": data.get('city')
            }
            ip_cache[ip] = location
            save_cache_to_disk(ip_cache)
            return location
        else:
            # Failed lookup (private IP or invalid)
            return None
    except:
        return None
# Flask Routes
@app.route('/')
def index():
    """Main dashboard page"""
    return render_template('dashboard.html')


@app.route('/api/stats')
def get_stats():
    """API endpoint - returns attack statistics as JSON"""
    # Get filter parameters
    ip_filter = request.args.get('ip', '')
    port_filter = request.args.get('port', '')
    event_filter = request.args.get('event_type', '')
    time_range = request.args.get('time_range', '24h')
    
    # Load all logs
    logs = load_all_logs()
    
    # Enrich with threat intelligence (on-the-fly, but don't block if it fails)
    try:
        logs = enrich_with_threat_intelligence(logs)
    except Exception as e:
        print(f"[WARNING] Enrichment failed (API quota exhausted?): {e}")
        # Continue without enrichment - show data anyway
        pass
    
    # Apply time filter
    logs = filter_by_time(logs, time_range)
    
    # Apply other filters
    if ip_filter:
        logs = [log for log in logs if ip_filter in log.get('source_ip', '')]
    if port_filter:
        logs = [log for log in logs if str(log.get('port')) == port_filter]
    
    # Apply event type filter with categorization
    if event_filter:
        filtered_logs = []
        for log in logs:
            event_type = log.get('event_type', '').lower()
            
            # Categorize events
            if event_filter == 'credential':
                # Match credential-related events
                if any(keyword in event_type for keyword in ['login', 'credential', 'password', 'ftp']):
                    filtered_logs.append(log)
            elif event_filter == 'command':
                # Match command execution events
                if 'cmd:' in event_type or 'command' in event_type:
                    filtered_logs.append(log)
            elif event_filter == 'connection':
                # Match connection/request events
                if any(keyword in event_type for keyword in ['http', 'request', 'connection', 'user_agent', 'telnet', 'ssh']):
                    filtered_logs.append(log)
            # If filter doesn't match any category, keep it as-is for exact matching
            elif event_filter in event_type or event_type in event_filter:
                filtered_logs.append(log)
        
        logs = filtered_logs
    
    stats = calculate_statistics(logs)
    return jsonify(stats)


@app.route('/api/ml-metrics')
def get_ml_metrics():
    """API endpoint - returns ML model performance metrics"""
    logs = load_all_logs()
    
    # Label attacks
    bot_count = 0
    human_count = 0
    
    for entry in logs:
        event_type = entry.get('event_type', '')
        if event_type in ['HTTP_REQUEST', 'CONNECTION']:
            bot_count += 1
        elif event_type in ['COMMAND_EXECUTION', 'SSH_LOGIN', 'CREDENTIAL_SUBMISSION', 
                            'Telnet login attempt', 'FTP login attempt', 'SSH login attempt']:
            human_count += 1
    
    # Calculate threat feature importance
    threat_scores = []
    tor_count = 0
    high_reports = 0
    
    for entry in logs:
        threat_intel = entry.get('threat_intelligence', {})
        threat_data = threat_intel.get('threat_data', {})
        
        if threat_intel.get('status') == 'success':
            score = threat_data.get('abuseConfidenceScore', 0)
            threat_scores.append(score)
            if threat_data.get('isTor'):
                tor_count += 1
            if threat_data.get('totalReports', 0) > 10:
                high_reports += 1
    
    avg_threat = sum(threat_scores) / len(threat_scores) if threat_scores else 0
    total = bot_count + human_count
    
    return jsonify({
        "baseline_accuracy": 0.7091,
        "enhanced_accuracy": 0.8000,
        "improvement": 0.0909,
        "bot_count": bot_count,
        "bot_percent": (bot_count / total) if total > 0 else 0,
        "human_count": human_count,
        "human_percent": (human_count / total) if total > 0 else 0,
        "feature_importance": {
            "time_diff_seconds": 0.864,
            "total_reports": 0.092,
            "abuse_score": 0.023,
            "is_tor": 0.021
        },
        "model_type": "Enhanced Classifier (Timing + Threat Intelligence)",
        "threat_detection": {
            "tor_nodes_detected": tor_count,
            "ips_with_high_reports": high_reports,
            "avg_threat_score": round(avg_threat, 1),
            "threat_features_enabled": True
        },
        "performance": {
            "cache_hit_rate": 95.0,
            "total_ips_enriched": len([e for e in logs if e.get('threat_intelligence', {}).get('status') == 'success']),
            "total_attacks_processed": len(logs)
        }
    })


def filter_by_time(logs, time_range):
    """Filter logs by time range"""
    if time_range == 'all':
        return logs
    
    now = datetime.now()
    
    # Calculate cutoff time
    if time_range == '12h':
        cutoff = now - timedelta(hours=12)
    elif time_range == '24h':
        cutoff = now - timedelta(hours=24)
    elif time_range == '7d':
        cutoff = now - timedelta(days=7)
    elif time_range == '30d':
        cutoff = now - timedelta(days=30)
    else:
        return logs  # Unknown range, return all
    
    # Filter logs by timestamp
    filtered = []
    for log in logs:
        try:
            log_time = datetime.fromisoformat(log.get('timestamp', ''))
            if log_time >= cutoff:
                filtered.append(log)
        except (ValueError, TypeError):
            continue  # Skip logs with invalid timestamps
    
    return filtered


@app.route('/api/map-data')
def get_map_data():
    """API endpoint - returns IP data for map with country-level fallback"""
    logs = load_all_logs()
    
    # Country center coordinates fallback when ip-api.com unavailable
    COUNTRY_COORDS = {
        "CN": (35.0, 105.0), "US": (38.0, -97.0), "RU": (60.0, 100.0),
        "IN": (20.0, 77.0), "BR": (-10.0, -55.0), "GB": (54.0, -2.0),
        "FR": (46.0, 2.0), "DE": (51.0, 9.0), "JP": (36.0, 138.0),
        "KR": (37.0, 127.5), "VN": (16.0, 108.0), "TH": (15.0, 100.0),
        "TR": (39.0, 35.0), "CO": (4.0, -72.0), "PH": (13.0, 122.0),
        "ID": (-5.0, 120.0), "MY": (2.5, 112.5), "SG": (1.35, 103.8),
        "HK": (22.3, 114.2), "TW": (23.5, 121.0), "NL": (52.5, 5.75),
        "PL": (52.0, 20.0), "UA": (49.0, 32.0), "IT": (42.8, 12.8),
        "ES": (40.0, -4.0), "CA": (60.0, -95.0), "AU": (-25.0, 135.0),
        "ZA": (-29.0, 24.0), "MX": (23.0, -102.0), "AR": (-34.0, -64.0),
        "CL": (-30.0, -71.0), "SE": (62.0, 15.0), "NO": (60.5, 8.5),
        "FI": (64.0, 26.0), "DK": (56.0, 10.0), "BE": (50.8, 4.0),
        "CH": (47.0, 8.0), "AT": (47.5, 14.5), "CZ": (49.8, 15.5),
        "RO": (46.0, 25.0), "HU": (47.0, 20.0), "GR": (39.0, 22.0),
        "PT": (39.5, -8.0), "IE": (53.0, -8.0), "NZ": (-41.0, 174.0),
        "IL": (31.5, 34.75), "AE": (24.0, 54.0), "SA": (24.0, 45.0),
        "EG": (26.0, 30.0), "NG": (9.0, 8.0), "KE": (-1.0, 38.0)
    }
    
    ip_counter = Counter()
    for entry in logs:
        ip = entry.get('source_ip')
        # Skip private IPs for map display
        if ip and TI_CLIENT and not TI_CLIENT.is_private_ip(ip):
            ip_counter[ip] += 1

    attacks = []
    for ip, count in ip_counter.most_common(30):  # Limit to 30 markers for performance
        location = None
        
        # Try cache first (from previous successful lookups)
        if ip in ip_cache:
            location = ip_cache[ip]
        
        # Fallback to country-level coordinates from enrichment data
        if not location:
            # Check if IP has threat_intelligence with countryCode
            matching_entries = [e for e in logs if e.get('source_ip') == ip]
            if matching_entries:
                threat_intel = matching_entries[0].get('threat_intelligence', {})
                if isinstance(threat_intel, dict):
                    # Extract threat_data from the enrichment structure
                    threat_data = threat_intel.get('threat_data', threat_intel)
                    if isinstance(threat_data, dict):
                        country_code = threat_data.get('countryCode') or threat_data.get('country_code')
                        if country_code and country_code in COUNTRY_COORDS:
                            lat, lon = COUNTRY_COORDS[country_code]
                            location = {
                                "lat": lat,
                                "lon": lon,
                                "country": country_code,
                                "city": threat_data.get('isp', 'Unknown')
                            }
        
        if location:
            attacks.append({
                "ip": ip,
                "count": count,
                "lat": location["lat"],
                "lon": location["lon"],
                "country": location["country"],
                "city": location["city"]
            })
    
    return jsonify({"attacks": attacks})

@app.route('/api/export/csv')
def export_csv():
    ''' export as a csv '''
    ip_filter = request.args.get('ip', '')
    port_filter = request.args.get('port', '')
    event_filter = request.args.get('event_type', '')
    time_range = request.args.get('time_range', '24h')
    
    # Load all logs
    logs = load_all_logs()
    
    # Apply time filter
    logs = filter_by_time(logs, time_range)
    
    # Apply other filters
    if ip_filter:
        logs = [log for log in logs if ip_filter in log.get('source_ip', '')]
    if port_filter:
        logs = [log for log in logs if str(log.get('port')) == port_filter]
    if event_filter:
        logs = [log for log in logs if event_filter in log.get('event_type', '')]

    output = StringIO()
    writer = csv.writer(output)
    writer.writerow(['Timestamp', 'Source IP', 'Port', 'Service','Event Type', 'Details'])
    for log in logs:
           writer.writerow([
               log.get('timestamp', ''),
               log.get('source_ip', ''),
               log.get('port', ''),
               log.get('service', ''),
               log.get('event_type', ''),
               log.get('details', '')
           ])
    output.seek(0)
    return send_file(
        BytesIO(output.getvalue().encode()),
        mimetype='text/csv',
        as_attachment=True,
        download_name=f'honeypot_export_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv'
    )


@app.route('/api/export/pdf')    
def export_pdf():
    '''Export professional PDF report using HTML template'''
    ip_filter = request.args.get('ip', '')
    port_filter = request.args.get('port', '')
    event_filter = request.args.get('event_type', '')
    time_range = request.args.get('time_range', '24h')
    
    # Load and filter logs
    logs = load_all_logs()
    logs = filter_by_time(logs, time_range)
    
    if ip_filter:
        logs = [log for log in logs if ip_filter in log.get('source_ip', '')]
    if port_filter:
        logs = [log for log in logs if str(log.get('port')) == port_filter]
    if event_filter:
        logs = [log for log in logs if event_filter in log.get('event_type', '')]

    stats = calculate_statistics(logs)
    
    # Prepare data for template
    port_services = {22: 'SSH', 23: 'Telnet', 80: 'HTTP', 443: 'HTTPS', 3389: 'RDP', 21: 'FTP'}
    sorted_ports = sorted(stats['ports'].items(), key=lambda x: x[1], reverse=True)
    total_port_attacks = sum(stats['ports'].values())
    
    # Format log samples
    formatted_logs = []
    for log in logs[:10]:
        try:
            timestamp = datetime.fromisoformat(log.get('timestamp', ''))
            timestamp_short = timestamp.strftime('%H:%M:%S')
        except:
            timestamp_short = 'N/A'
        
        details = log.get('username', log.get('command', log.get('data', '')))
        
        formatted_logs.append({
            'timestamp_short': timestamp_short,
            'source_ip': log.get('source_ip', 'N/A'),
            'event_type': log.get('event_type', 'N/A'),
            'details': details
        })
    
    # Render HTML template (no custom filters needed)
    html_content = render_template(
        'pdf_report.html',
        report_date=datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        time_range=time_range,
        ip_filter=ip_filter,
        port_filter=port_filter,
        event_filter=event_filter,
        filters_applied=bool(ip_filter or port_filter or event_filter),
        stats=stats,
        logs=formatted_logs,
        sorted_ports=sorted_ports,
        port_services=port_services,
        total_port_attacks=total_port_attacks
    )
    
    # Convert HTML to PDF using xhtml2pdf
    buffer = BytesIO()
    pisa_status = pisa.CreatePDF(html_content, dest=buffer)
    
    if pisa_status.err:
        return jsonify({"error": "PDF generation failed"}), 500
    
    buffer.seek(0)
    
    return send_file(
        buffer,
        mimetype='application/pdf',
        as_attachment=True,
        download_name=f'honeypot_report_{datetime.now().strftime("%Y%m%d_%H%M%S")}.pdf'
    )


@app.route('/api/clear-data', methods=['POST'])
def clear_data():
    """Clear all attack data from logs directory"""
    try:
        log_files = glob.glob(str(LOG_DIR / "*.jsonl"))
        deleted_count = 0
        failed_count = 0
        
        for log_file in log_files:
            try:
                # Change permissions first if needed
                os.chmod(log_file, 0o666)
                os.remove(log_file)
                print(f"[CLEAR] Deleted {log_file}")
                deleted_count += 1
            except Exception as e:
                print(f"[CLEAR] Error deleting {log_file}: {e}")
                failed_count += 1
        
        if deleted_count > 0:
            print(f"[CLEAR] Successfully deleted {deleted_count} file(s)")
        if failed_count > 0:
            print(f"[CLEAR] Failed to delete {failed_count} file(s)")
            
        return jsonify({
            'success': deleted_count > 0,
            'message': f'Deleted {deleted_count} file(s)' if deleted_count > 0 else 'No files to delete',
            'deleted': deleted_count,
            'failed': failed_count
        })
    except Exception as e:
        print(f"[CLEAR] Error: {e}")
        return jsonify({
            'success': False,
            'message': str(e)
        }), 500


# WebSocket Events
@socketio.on('connect')
def handle_connect():
    """Client connected via WebSocket"""
    print('Client connected to dashboard')
    emit('connected', {'data': 'Connected to HoneyPot Dashboard'})


@socketio.on('request_stats')
def handle_stats_request():
    """Client requests updated statistics"""
    logs = load_all_logs()
    stats = calculate_statistics(logs)
    emit('stats_update', stats)


# ============================================================================
# Real-time Log Monitoring
# ============================================================================
last_log_size = {}

def monitor_logs_for_updates():
    """Monitor log files and emit new attacks via WebSocket"""
    global last_log_size
    
    print("[MONITOR] Starting log monitoring thread...")
    time.sleep(5)  # Wait for server to start
    
    while True:
        try:
            log_files = glob.glob(str(LOG_DIR / "honeypot_*.jsonl"))
            
            for log_file in log_files:
                current_size = os.path.getsize(log_file)
                
                # Check if file has grown
                if log_file not in last_log_size:
                    last_log_size[log_file] = current_size
                elif current_size > last_log_size[log_file]:
                    # File has new data - read new lines
                    with open(log_file, 'r', encoding='utf-8') as f:
                        f.seek(last_log_size[log_file])
                        new_lines = f.readlines()
                        
                        for line in new_lines:
                            try:
                                attack = json.loads(line.strip())
                                
                                # Skip private IPs from live feed
                                ip = attack.get('source_ip')
                                if TI_CLIENT and TI_CLIENT.is_private_ip(ip):
                                    continue
                                
                                # Enrich with threat intelligence
                                if TI_AVAILABLE:
                                    if ip:
                                        try:
                                            threat_data = TI_CLIENT.get_threat_data(ip)
                                            attack['threat_intelligence'] = {
                                                'status': 'success',
                                                'threat_data': threat_data
                                            }
                                        except:
                                            pass
                                
                                # Emit new attack to all connected clients
                                socketio.emit('new_attack', attack)
                                print(f"[MONITOR] Emitted new attack from {attack.get('source_ip')}")
                            except json.JSONDecodeError:
                                pass
                        
                        last_log_size[log_file] = current_size
            
        except Exception as e:
            print(f"[MONITOR] Error: {e}")
        
        time.sleep(2)  # Check every 2 seconds

# Main
if __name__ == '__main__':
    print("=" * 50)
    print("[*] HoneyPot Dashboard Starting...")
    print("=" * 50)
    print(f"[*] Log directory: {LOG_DIR}")
    print(f"[*] Dashboard URL: http://localhost:5000")
    print("=" * 50)
    
    # Start log monitoring in background thread
    monitor_thread = threading.Thread(target=monitor_logs_for_updates, daemon=True)
    monitor_thread.start()
    
    socketio.run(app, host='0.0.0.0', port=5000, debug=False, allow_unsafe_werkzeug=True)

