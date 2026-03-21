# HoneyPot Web Dashboard - Project Status & Plan

## 📌 SESSION RULES (READ THIS FIRST!)
1. **Learning Mode:** User wants to learn - NO copy-paste code solutions
2. **Guidance Only:** Explain concepts, suggest approaches, point to docs
3. **This File:** Single source of truth for project status
4. **Progress Tracking:** Update checkboxes as features are completed
5. **Next Session:** Read this file first to understand current state

---

## 🎯 Project Goal
Real-time web dashboard monitoring honeypot attacks with:
- Live log streaming via WebSockets
- GeoIP attack map (Leaflet.js)
- Port/service statistics
- Credential captures highlighted
- Dark hacker theme UI

## 👥 Roles
- **User (Backend):** Flask, WebSockets, GeoIP, data processing, API endpoints
- **Assistant:** Guidance, explanations, code review, suggestions

---

## ✅ CURRENT PROJECT STATUS

### Core Infrastructure: ✅ COMPLETE
- [x] Flask app setup (`src/dashboard.py`)
- [x] Folder structure (`web/templates/`, `web/static/`)
- [x] Dependencies installed (flask, flask-socketio, requests, eventlet)

### Backend Features: ✅ COMPLETE
- [x] Log reading system (`load_all_logs()`)
- [x] Statistics calculation (`calculate_statistics()`)
- [x] GeoIP lookups (ip-api.com with caching)
- [x] API endpoints: `/`, `/api/stats`, `/api/map-data`
- [x] WebSocket real-time support
- [x] IP location cache system

### Frontend Features: ✅ COMPLETE
- [x] Main dashboard UI (`web/templates/dashboard.html`)
- [x] Professional dark theme CSS with glassmorphism (`web/static/css/style.css`)
- [x] Real-time JavaScript client (`web/static/js/dashboard.js`)
- [x] Leaflet.js map integration with markers
- [x] Chart.js visualizations
- [x] Socket.IO client connection
- [x] Auto-refresh every 5 seconds (only animates on data change)
- [x] Interactive map with popups showing IP/location/count
- [x] Live attack feed with colored events (commands, credentials, normal)
- [x] Styled Top IPs list with animations
- [x] Smooth number counting animations
- [x] Micro-interactions and hover effects

### What Works Right Now:
✅ Dashboard runs: `python src\dashboard.py`
✅ UI loads: http://localhost:5000
✅ Reads logs from `logs/honeypot_*.jsonl`
✅ Shows statistics, map, charts
✅ Real-time WebSocket updates
✅ GeoIP location plotting
✅ Live attack feed with colored events
✅ Filtering by IP, Port, Event Type, Time Range
✅ Timeline chart adapts to time range selection
✅ Professional UI with animations and micro-interactions

---

## 🚀 FUTURE ROADMAP

### 🎯 Quick Wins (30-60 min each):
- [ ] 🔔 Browser Notifications - Desktop alerts for new attacks
- [ ] 🔊 Sound Alerts - Audio notification for credential captures
- [x] 📥 Export to CSV - Download attack logs as spreadsheet
- [x] 📄 Export to PDF - Generate PDF reports
- [ ] 📊 Attack Heatmap - Visual intensity map of attack sources

### 🚀 Medium Projects (1-2 hours):
- [ ] 🔐 Authentication System - Login/logout, protect dashboard
- [ ] 📧 Email Alerts - Send emails on suspicious activity
- [ ] 🎨 Custom Themes - Light/Dark mode toggle
- [ ] 📱 Mobile Responsive - Better phone/tablet experience
- [ ] 🌍 Geolocation Heatmap - Heat intensity based on attack frequency
- [ ] 📈 Historical Comparison - Compare this week vs last week

### 🧠 Advanced Features (ML Learning Path - 2+ hours):
- [ ] 🤖 Threat Intelligence Integration - AbuseIPDB, VirusTotal API lookup
- [ ] 🔍 Pattern Detection - Identify attack patterns automatically
- [ ] 🎯 Anomaly Detection - ML-based unusual behavior detection
- [ ] 📊 Predictive Analytics - Forecast attack trends
- [ ] 🧪 Attack Classification - ML model to categorize attack types
- [ ] 🌐 Multi-Honeypot Support - Manage multiple honeypot instances

### 💾 Data & Performance:
- [ ] 🗄️ Database Integration - Move from JSONL to PostgreSQL/MongoDB
- [ ] ⚡ Performance Optimization - Handle 10k+ logs efficiently
- [ ] 🔄 Auto-Archive - Compress old logs automatically
- [ ] 📦 Backup System - Automated log backups

---

## 📦 Dependencies (Already Installed)

### Backend (Python)
```bash
pip install flask flask-socketio requests eventlet
```

### Frontend (CDN - loaded automatically)
- Leaflet.js (maps)
- Chart.js (graphs)
- Socket.IO client

---

## 📁 Project Structure

```
C:\projects\HoneyPot\
├── src/
│   ├── honeypot.py          # SSH/Telnet honeypot server
│   ├── dashboard.py         # Flask backend (THIS IS THE MAIN APP)
│   └── analyze_logs.py      # Log analysis utilities
│
├── web/
│   ├── templates/
│   │   └── dashboard.html   # Main UI
│   ├── static/
│   │   ├── css/
│   │   │   └── style.css    # Dark theme styles
│   │   └── js/
│   │       └── dashboard.js # Real-time client code
│   └── fake_website.html    # HTTP honeypot page
│
├── logs/                     # JSONL attack logs (auto-generated)
├── data/
│   └── ip_cache.json        # Cached GeoIP lookups
├── docker-compose.yml       # Docker orchestration
├── Dockerfile               # Main container
└── requirements.txt         # Python dependencies
```

---

## 🏗️ Architecture Overview

```
┌──────────────┐
│   Honeypot   │ (ports 21,22,23,80) - honeypot.py
│              │ Attackers connect here
└──────┬───────┘
       │ Writes JSONL logs
       ↓
┌──────────────────┐
│  logs/*.jsonl    │ One file per day
│                  │ JSON Lines format
└──────┬───────────┘
       │ Flask reads periodically
       ↓
┌──────────────────┐
│  dashboard.py    │ (port 5000)
│  Flask + SocketIO│
│  • load_all_logs()
│  • GeoIP lookup
│  • REST APIs
│  • WebSocket
└──────┬───────────┘
       │ HTTP/WebSocket
       ↓
┌──────────────────┐
│    Browser       │ localhost:5000
│  dashboard.html  │
│  • Leaflet map
│  • Chart.js graphs
│  • Socket.IO client
└──────────────────┘
```

---

## 🔨 Key Implementation Details

### Backend (`src/dashboard.py`)

**Main Functions:**
- `load_all_logs()` - Reads all JSONL files from logs/, parses JSON
- `calculate_statistics(logs)` - Aggregates attack data, counts ports/IPs
- `lookup_ip_location(ip)` - GeoIP via ip-api.com, saves to cache
- Flask routes: `/` (HTML), `/api/stats` (JSON), `/api/map-data` (JSON)
- SocketIO events: `connect`, `request_stats`

**GeoIP Caching:**
- Cache file: `data/ip_cache.json`
- Avoids rate limits on ip-api.com
- Persists across restarts

### Frontend (`web/static/js/dashboard.js`)

**Key Features:**
- Socket.IO connection to Flask backend
- Auto-refresh stats every 5 seconds
- Leaflet map with markers for each IP
- Chart.js: Port distribution (pie), Timeline (bar)
- Real-time connection status indicator

---

## 📊 API Endpoints Reference

### `GET /`
Returns: HTML dashboard page

### `GET /api/stats`
Returns JSON:
```json
{
  "total_attacks": 1234,
  "ports": {"22": 500, "23": 400, "80": 334},
  "top_ips": [{"ip": "1.2.3.4", "count": 100}],
  "credentials_captured": 45,
  "recent_events": [...]
}
```

### `GET /api/map-data`
Returns JSON:
```json
{
  "attacks": [
    {
      "ip": "1.2.3.4",
      "lat": 40.7128,
      "lon": -74.0060,
      "country": "US",
      "city": "New York",
      "count": 10
    }
  ]
}
```

### WebSocket Events
- Client → Server: `request_stats` (manual refresh)
- Server → Client: `stats_update` (push new data)
- Server → Client: `connected` (confirmation message)

---

## 🚀 How to Run

### Start Dashboard:
```bash
cd C:\projects\HoneyPot
python src\dashboard.py
```

Visit: **http://localhost:5000**

### Start Honeypot (separate terminal):
```bash
python src\honeypot.py
```

### Generate Test Data:
```bash
python add_test_attacks.py
```

---

## 🎓 Learning Resources

**Flask:** https://flask.palletsprojects.com/
**Flask-SocketIO:** https://flask-socketio.readthedocs.io/
**Leaflet.js:** https://leafletjs.com/reference.html
**Chart.js:** https://www.chartjs.org/docs/
**Socket.IO Client:** https://socket.io/docs/v4/client-api/

---

## 🐛 Troubleshooting

**Dashboard won't start:**
- Check dependencies: `pip install flask flask-socketio requests eventlet`
- Check Python version: `python --version` (need 3.7+)

**No data showing:**
- Check logs exist: `dir logs\honeypot_*.jsonl`
- Run test script: `python add_test_attacks.py`

**Map not loading:**
- Check internet connection (needs ip-api.com)
- Check browser console for errors (F12)

**WebSocket "Disconnected":**
- Restart dashboard
- Check port 5000 not in use: `netstat -ano | findstr :5000`

---

## 📌 What to Work On Next?

The core dashboard is done! Possible next projects:

1. **Add authentication** - Learn Flask-Login
2. **Real-time alerting** - Email/SMS when attack detected
3. **Advanced filtering** - Search by IP, port, date range
4. **Export features** - PDF reports, CSV downloads
5. **Performance** - Pagination for large log files
6. **More protocols** - FTP commands, HTTP paths analysis

---

**Last Updated:** 2026-02-11 20:06 UTC
**Status:** ✅ FEATURE COMPLETE - READY FOR ENHANCEMENTS
