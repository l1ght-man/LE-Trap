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

# Flask Configuration
app = Flask(__name__, 
            template_folder='../web/templates',
            static_folder='../web/static')
app.config['SECRET_KEY'] = 'honeypot-secret-key-change-this'

# SocketIO for real-time updates
socketio = SocketIO(app, cors_allowed_origins="*")

# Paths - Use absolute paths to avoid issues
SCRIPT_DIR = Path(__file__).parent.resolve()
LOG_DIR = SCRIPT_DIR.parent / "logs"

print(f"[INIT] Log directory: {LOG_DIR}")
print(f"[INIT] Exists: {LOG_DIR.exists()}")


def load_all_logs():
    """Read all JSONL log files and return as list"""
    all_logs = []
    log_files = glob.glob(str(LOG_DIR / "honeypot_*.jsonl"))
    
    print(f"[DEBUG] Found {len(log_files)} log files")
    
    for log_file in log_files:
        try:
            with open(log_file, 'r', encoding='utf-8') as f:
                for line in f:
                    try:
                        log_entry = json.loads(line.strip())
                        all_logs.append(log_entry)
                    except json.JSONDecodeError:
                        continue
        except FileNotFoundError:
            continue
    
    print(f"[DEBUG] Loaded {len(all_logs)} total entries")
    return all_logs


def calculate_statistics(logs):
    """Calculate attack statistics from logs"""
    if not logs:
        return {
            "total_attacks": 0,
            "ports": {},
            "top_ips": [],
            "credentials_captured": 0,
            "recent_events": []
        }
    
    port_counter = Counter()
    ip_counter = Counter()
    credentials_count = 0
    
    for entry in logs:
        port = entry.get('port')
        if port:
            port_counter[port] += 1
        
        ip = entry.get('source_ip')
        if ip:
            ip_counter[ip] += 1
        
        if 'credentials' in entry:
            credentials_count += 1
    
    top_ips = [{"ip": ip, "count": count} for ip, count in ip_counter.most_common(10)]
    recent_events = sorted(logs, key=lambda x: x.get('timestamp', ''), reverse=True)[:20]
    
    return {
        "total_attacks": len(logs),
        "ports": dict(port_counter),
        "top_ips": top_ips,
        "credentials_captured": credentials_count,
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
    
    # Apply time filter
    logs = filter_by_time(logs, time_range)
    
    # Apply other filters
    if ip_filter:
        logs = [log for log in logs if ip_filter in log.get('source_ip', '')]
    if port_filter:
        logs = [log for log in logs if str(log.get('port')) == port_filter]
    if event_filter:
        logs = [log for log in logs if event_filter in log.get('event_type', '')]
    
    stats = calculate_statistics(logs)
    return jsonify(stats)


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
    """API endpoint - returns IP data for map (GeoIP to be added in Phase 3)"""
    logs = load_all_logs()
    
    ip_counter = Counter()
    for entry in logs:
        ip = entry.get('source_ip')
        if ip:
            ip_counter[ip] += 1

     
    attacks = []
    for ip, count in ip_counter.most_common(50):
        location = lookup_ip_location(ip)
        attack_data ={
            "ip": ip,
            "count": count,
            }
        if location:
           attack_data["lat"] = location["lat"]
           attack_data["lon"] = location["lon"]
           attack_data["country"] = location["country"]
           attack_data["city"] = location["city"]
        attacks.append(attack_data)
    
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
    print("🐻 HoneyPot Dashboard Starting...")
    print("=" * 50)
    print(f"📂 Log directory: {LOG_DIR}")
    print(f"🌐 Dashboard URL: http://localhost:5000")
    print("=" * 50)
    
    # Start log monitoring in background thread
    monitor_thread = threading.Thread(target=monitor_logs_for_updates, daemon=True)
    monitor_thread.start()
    
    socketio.run(app, host='0.0.0.0', port=5000, debug=True)
