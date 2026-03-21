# LE-Trap: Enterprise Threat Intelligence Platform

[![Python 3.8+](https://img.shields.io/badge/Python-3.8%2B-blue)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Status: Active](https://img.shields.io/badge/Status-Active-success)]()
[![Docker](https://img.shields.io/badge/Build-Docker-2496ED)]()
[![GitHub](https://img.shields.io/badge/GitHub-l1ght--man-black)](https://github.com/l1ght-man)

Advanced honeypot system with real-time threat intelligence, machine learning classification, and interactive security dashboard. Automatically enrich attack data with IP reputation scores, geolocation, and bot detection.

---

## The Problem

Security teams struggle with:
- ❌ Manually correlating attack patterns across multiple services
- ❌ Determining if attackers are automated bots or human reconnaissance
- ❌ Querying threat intelligence APIs for each suspicious IP
- ❌ Generating actionable security reports without expensive SIEM tools
- ❌ Monitoring honeypot activity in real-time with visual insights

## The Solution

**HoneyPot** provides:
- ✅ Multi-service honeypot (SSH, HTTP, FTP, Telnet) capturing 485+ attacks
- ✅ Automatic threat intelligence enrichment from AbuseIPDB, GeoIP, Tor detection
- ✅ ML classification (80% accuracy) distinguishing bots from human attackers
- ✅ Interactive dashboard with filtering, threat scoring, live attack timeline
- ✅ PDF report generation for compliance and incident documentation

---

## Quick Start

### Requirements
- Python 3.8+ (3.11 recommended)
- Docker & Docker Compose (recommended)
- 1GB RAM minimum, 2GB recommended
- Linux/macOS/Windows with WSL2

### Option 1: Docker (Recommended - 3 minutes)

```bash
git clone https://github.com/l1ght-man/LE-Trap.git
cd LE-Trap
docker-compose up -d
open http://localhost:5000
```

### Option 2: Local Installation

```bash
git clone https://github.com/l1ght-man/LE-Trap.git
cd LE-Trap
pip install -r requirements.txt
export ABUSEIPDB_API_KEY=your_key_here
python src/honeypot.py &
python src/dashboard.py
open http://localhost:5000
```

### First Real Attack

```bash
# Trigger an attack
ssh -o StrictHostKeyChecking=no root@localhost -p 22

# View dashboard
# You'll see: attack logged, IP geolocated, threat score calculated
```

---

## Features at a Glance

| Feature | Details |
|---------|---------|
| **Multi-Service Honeypot** | SSH, HTTP, FTP, Telnet with realistic responses |
| **Threat Intelligence** | Real-time IP reputation via AbuseIPDB + Tor detection |
| **Machine Learning** | 80% accuracy bot vs human classification |
| **Interactive Dashboard** | Live attacks, maps, filtering, statistics |
| **Reporting** | Professional PDF reports + CSV export |
| **Performance** | 485 attacks analyzed in <1 second |
| **Scalability** | Hybrid caching (95%+ API reduction) |

---

## Architecture Overview

```
LE-Trap
    │ (Network Traffic)
    ▼
Honeypot Traps ── SSH, HTTP, FTP, Telnet
    │ (Raw Logs)
    ▼
Data Enrichment ─── IP Reputation, Geolocation, Threat Scoring
    │ (Enriched Data)
    ▼
ML Classification ─ Bot vs Human Detection
    │ (Classified Data)
    ├── Dashboard (Real-time UI)
    ├── PDF Reports (Compliance)
    └── CSV Export (Analysis)
```

---

## Usage

### Dashboard

```
1. Open http://localhost:5000
2. See live attack feed (5-second refresh)
3. Filter by: Time, IP, Port, Event Type
4. View threat scores, geolocation map, statistics
5. Export as PDF or CSV
```

### CLI

```bash
# Analyze attacks
python src/analyze_logs.py

# Clean raw logs
python src/clean_logs.py

# Enrich with threat data
python src/enrichment_worker.py

# Run ML tests
python ml/test_all_ml.py
```

### API

```bash
# Get statistics
curl http://localhost:5000/api/stats?time_range=24h

# Get threat data
curl http://localhost:5000/api/ml-metrics

# Export data
curl http://localhost:5000/api/export/pdf?port=22 > report.pdf
curl http://localhost:5000/api/export/csv > attacks.csv
```

---

## Configuration

### Environment Variables

```bash
export ABUSEIPDB_API_KEY=your_api_key
export LOG_LEVEL=INFO
export FLASK_ENV=production
```

Get your free API key: https://www.abuseipdb.com/register

### Docker Compose

```bash
docker-compose up -d              # Start all services
docker-compose logs -f            # View logs
docker-compose down               # Stop services
docker-compose -f docker-compose.prod.yml up -d  # Production
```

---

## Performance Benchmarks

- **485 attacks** analyzed in <1 second
- **7 IPs geolocated** (4 private filtered)
- **195 threat scores** fetched from API
- **3-page PDF** generated in <2 seconds
- **Dashboard refresh** every 5 seconds smoothly

---

## Security

### Threat Model - Defends Against:
- Automated scanners (Shodan, Censys)
- Brute-force attacks (SSH password guessing)
- Credential stuffing
- Distributed attacks (botnets)
- Reconnaissance probes

### NOT Designed For:
- Nation-state adversaries with 0-days
- Insider threats
- Supply chain attacks
- Sophisticated evasion techniques

### Best Practices

- Run in isolated network (DMZ, separate VLAN)
- Never expose dashboard to internet without VPN
- Rotate API keys monthly
- Use TLS for all communications
- Keep dependencies updated

---

## Machine Learning

### Model Performance
- **Baseline:** 70.91% accuracy (timing patterns only)
- **Enhanced:** 80.00% accuracy (+ threat intelligence)
- **Improvement:** +9.09 percentage points

### Feature Importance
- Time-based patterns: 86.4%
- Abuse score: 9.2%
- Total reports: 2.3%
- Tor flag: 2.1%

### Testing
```bash
python ml/test_all_ml.py
# TEST 1: Threat Intelligence ✓
# TEST 2: Data Pipeline ✓
# TEST 3: Attack Classification ✓
# TEST 4: Enhanced Classifier ✓
```

See [ml/README.md](ml/README.md) for detailed ML documentation.

---

## File Structure

```
honeypot/
├── src/                         # Core application
│   ├── honeypot.py             # Honeypot server
│   ├── dashboard.py            # Flask dashboard
│   ├── enrichment_worker.py    # Threat intelligence
│   ├── clean_logs.py           # Log cleaning
│   └── analyze_logs.py         # Log analysis
├── ml/                         # Machine learning
│   ├── models/                 # Trained models
│   ├── train_classifier.py    # Model training
│   ├── test_all_ml.py         # Test suite
│   └── README.md              # ML documentation
├── web/                        # Dashboard UI
│   ├── templates/             # HTML templates
│   ├── static/                # CSS & JavaScript
│   └── fake_website.html      # Honeypot landing page
├── data/                       # Logs & cache
│   └── enriched_real_attacks.jsonl
├── docker-compose.yml         # Docker configuration
├── requirements.txt           # Python dependencies
└── README.md                  # This file
```

---

## Troubleshooting

### "Connection refused" on dashboard
```bash
ps aux | grep dashboard.py
python src/dashboard.py
```

### API rate limited
The system automatically uses cached data. No action needed!

### Map not showing locations
Some IPs may not have geolocation data. This is expected.

### Private IPs showing as threats
Intentional filtering (192.168.x, 10.x, etc.) to save API quota.

---

## Testing

```bash
# Run all tests
python ml/test_all_ml.py

# Individual tests
pytest tests/ -v
pytest ml/ -v --cov

# Generate coverage report
pytest --cov=src --cov=ml --html=report.html
```

---

## Installation

### Docker

```bash
docker-compose up -d
docker exec honeypot-main python src/clean_logs.py
docker exec honeypot-ml python src/enrichment_worker.py
```

### Manual

```bash
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate
pip install -r requirements.txt
python src/honeypot.py &
python src/dashboard.py
```

---

## Contributing

We welcome contributions:

1. Fork the repository
2. Create a branch: `git checkout -b feature/your-feature`
3. Write tests for your changes
4. Ensure all tests pass: `pytest`
5. Submit a pull request

---

## License

MIT License - See [LICENSE](LICENSE) file for details.

This tool is for authorized security research and defensive purposes only. Unauthorized access to computer systems is illegal.

---

## Support

- **Issues:** [GitHub Issues](https://github.com/l1ght-man/LE-Trap/issues)
- **Security:** Email security@example.com (do NOT open public issue)
- **Discussions:** [GitHub Discussions](https://github.com/l1ght-man/LE-Trap/discussions)

---

## Citation

```bibtex
@software{letrap2026,
  title={LE-Trap: Enterprise Threat Intelligence Platform},
  author={l1ght-man},
  year={2026},
  url={https://github.com/l1ght-man/LE-Trap}
}
```

---

**Status:** Production Ready | **Last Updated:** March 21, 2026 | **Author:** l1ght-man | **Maintained:** Yes
