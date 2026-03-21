import json
import glob
from pathlib import Path
from collections import Counter
import datetime

LOG_DIR = Path("../logs")
HTML_REPORT = "../reports/attack_report.html"

def load_logs ():
    all_logs = []
    for log_file in glob.glob(str(LOG_DIR / "honeypot_*.jsonl")):
        with open(log_file , 'r', encoding='utf-8') as f:
            for line in f:
                try:
                    all_logs.append(json.loads(line.strip()))
                except:
                    continue
    print(f"loaded {len(all_logs)} log entries")
    return all_logs
def analyse_logs (logs):
    ips = Counter(entry['source_ip'] for entry in logs)
    ports = Counter(entry['port'] for entry in logs)
    paths = Counter()
    agents = Counter()
    creds = Counter()
    for entry in logs :
        data = entry['details'].lower()

        if 'http get' in data or 'http post' in data :
            if "'" in data:
                path = data.split("'")[1].split("'")[0]
                paths[path]+=1
        if 'user-agent' in data :
            agent = data.split(':')[-1].split('...')[0]
            agents [agent] += 1
        if 'username' in data or 'user' in data :
            if any(x in data for x in ['user', 'pass', 'admin', 'root']):
                creds[data [0:50]] += 1
    return ips, ports, paths, agents, creds        

def generate_html_report(ips, ports, paths, agents, creds):
    """Create beautiful HTML dashboard"""
    html = f"""
<!DOCTYPE html>
<html>
<head>
    <title>Honeypot Attack Report - {datetime.date.today()}</title>
    <style>
        body{{font-family:Arial;background:#1a1a1a;color:#0f0;padding:20px}}
        .metric{{background:rgba(0,255,0,0.1);padding:20px;margin:10px 0;border-left:4px solid #0f0}}
        table{{width:100%;border-collapse:collapse;margin:10px 0}}
        th,td{{padding:8px;text-align:left;border-bottom:1px solid #333}}
        th{{background:#0f0;color:#000}}
        .top-ip{{color:#ff0;font-weight:bold}}
    </style>
</head>
<body>
    <h1>🐻 Honeypot Attack Dashboard</h1>
    
    <div class="metric">
        <h2>Total Attacks: {sum(ips.values())}</h2>
    </div>
    
    <h2>🥇 Top Attacking IPs</h2>
    <table>
        <tr><th>IP</th><th>Hits</th></tr>
"""
    
    for ip, count in ips.most_common(10):
        html += f"        <tr><td class='top-ip'>{ip}</td><td>{count}</td></tr>\n"
    
    html += """
    </table>
    
    <h2>🔌 Most Targeted Ports</h2>
    <table><tr><th>Port</th><th>Hits</th></tr>
"""
    for port, count in ports.most_common():
        service = {22:'SSH', 21:'FTP', 80:'HTTP'}.get(port, 'Unknown')
        html += f"        <tr><td>{service} ({port})</td><td>{count}</td></tr>\n"
    
    if paths:
        html += """
    </table><h2>🌐 Top HTTP Paths</h2>
    <table><tr><th>Path</th><th>Hits</th></tr>
"""
        for path, count in paths.most_common(10):
            html += f"        <tr><td>{path}</td><td>{count}</td></tr>\n"
    
    if agents:
        html += """
    </table><h2>🕷️ Top User-Agents/Scanners</h2>
    <table><tr><th>Agent</th><th>Hits</th></tr>
"""
        for agent, count in agents.most_common(10):
            html += f"        <tr><td>{agent}</td><td>{count}</td></tr>\n"
    
    html += """
    </table></body></html>
"""

    with open(HTML_REPORT , 'w' , encoding='utf-8')  as f:
        f.write(html)
    print(f" report saved {HTML_REPORT}")

if __name__ == '__main__':
    logs= load_logs()
    if logs:
        ips, ports, paths, agents, creds = analyse_logs(logs)
        generate_html_report(ips, ports, paths, agents, creds)
        print("analyse complete! open attack_report.html")
    else:
        print("No logs found - run honeypot first!")

