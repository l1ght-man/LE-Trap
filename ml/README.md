# Machine Learning Module

Comprehensive ML and threat intelligence integration for the LE-Trap security research tool.

## Key Results

### Model Performance
Generated during training with `python ml/train_classifier.py`:
- **Baseline Accuracy:** 70.91% (bot vs human classification)
- **Enhanced Accuracy:** 80.00% (with threat intelligence features)
- **Improvement:** +9.09 percentage points from adding threat data

### Sample Analysis Charts
```
ml/charts/
├── classifier_results.png          # Model performance comparison
├── enhanced_classifier_comparison.png  # Baseline vs enhanced accuracy
├── threat_score_distribution.png   # IP threat score distribution  
├── top_threats.png                 # Most malicious IPs detected
├── top_ips.png                     # Attack frequency by IP
├── attacks_by_hour.png             # Attack timing patterns
├── event_pie_chart.png             # Distribution of attack types
├── risk_categories.png             # Threat level breakdown
├── service_distribution.png        # Port/service analysis
└── timing_histogram.png            # Temporal attack patterns
```

Generate these charts locally by running:
```bash
python ml/train_classifier.py
python ml/01_exploratory_analysis.py
```

---

## Contents

```
ml/
├── models/
│   └── threat_intelligence.py      # AbuseIPDB API client with caching
├── test_all_ml.py                  # Comprehensive test suite (run this!)
├── test_threat_intel.py            # Legacy threat intelligence tests
├── train_classifier.py             # Enhanced classifier training
├── 01_exploratory_analysis.py      # Data analysis and visualization
├── 02_attack_classifier.py         # Basic bot vs human classifier
├── generate_synthetic_data.py      # Test data generation
├── check_stats.py                  # Statistics checker
└── data/                           # Training data and cache
    ├── synthetic_attacks.jsonl
    ├── enriched_attacks.jsonl
    ├── threat_cache.json           # Cached AbuseIPDB lookups
    └── ip_cache.json               # Cached IP enrichment
```

---

## 🚀 Quick Start

### 1. Run All ML Tests

```bash
cd C:\projects\HoneyPot
python ml/test_all_ml.py
```

This runs 4 comprehensive tests:
- **Test 1:** Threat Intelligence (IP reputation, Tor detection, caching)
- **Test 2:** Data Pipeline (Clean → Enrich workflow)
- **Test 3:** Attack Classification (Bot vs Human, 70.91% accuracy)
- **Test 4:** Enhanced Classifier (with threat intelligence, 80% accuracy)

### 2. Expected Output

```
================================================================================
🤖 COMPREHENSIVE ML MODEL TEST SUITE
================================================================================

TEST 1: Threat Intelligence ✅
  ✓ Private IPs: Correctly skipped (192.168.1.1, 10.0.0.1, etc.)
  ✓ Public IPs: Queried (8.8.8.8 Score: 0%, 1.1.1.1 Score: 0%)
  ✓ Malicious IP: 185.220.101.1 → Is Tor: True | Score: 100%
  ✓ Cache: 230 IPs cached, 95%+ hit rate

TEST 2: Data Pipeline ✅
  ✓ Cleaned attacks: 485 records
  ✓ Enriched attacks: 485 records with threat_intelligence
  ✓ Stats: avg 6.8%, max 100%, min 0%

TEST 3: Attack Classification ✅
  ✓ Bot attacks: 75 | Human attacks: 199
  ✓ Model accuracy: 70.91%
  ✓ Human recall: 100%

TEST 4: Enhanced Classifier ✅
  ✓ Baseline: 70.91% | Enhanced: 80.00%
  ✓ Improvement: +9.09 percentage points
  ✓ Most important feature: time_diff_seconds (86.4%)

✅ ML MODEL TEST SUITE COMPLETE
```

---

## 🔧 Configuration

### AbuseIPDB API Key

Set your API key in `.env`:

```bash
ABUSEIPDB_API_KEY=your_key_here
```

Get a free API key from: https://www.abuseipdb.com/register

### Caching Strategy

The ML module uses a **hybrid caching strategy**:

1. **Local File Cache** (`data/threat_cache.json`)
   - Persistent between runs
   - ~230 IPs cached after first enrichment
   - Reduces API calls by 95%+

2. **Memory Cache** (ThreatIntelligence class)
   - Fast lookups during session
   - Automatically populated from file cache

3. **Private IP Filtering**
   - Skips 192.168.x, 10.x, 172.16-31.x, 127.x
   - Saves API quota (these IPs aren't threats)

---

## 📊 Threat Intelligence Features

### AbuseIPDB Integration

```python
from ml.models.threat_intelligence import ThreatIntelligence

ti = ThreatIntelligence(api_key)

# Check an IP
threat_data = ti.get_threat_data("8.8.8.8")

# Returns:
{
    "status": "success",
    "threat_data": {
        "ipAddress": "8.8.8.8",
        "abuseConfidenceScore": 0,
        "isTor": false,
        "totalReports": 4,
        "countryCode": "US",
        "domain": "google.com",
        ...
    }
}

# Enrich an attack
attack = {
    "timestamp": "2026-03-21T...",
    "source_ip": "1.2.3.4",
    "port": 22,
    "service": "ssh"
}

enriched = ti.enrich_attack(attack)
# Now has "threat_intelligence" field!
```

### Scoring System

- **0-24%:** SAFE (green badge)
- **25-74%:** WARNING (orange badge)
- **75-100%:** CRITICAL (red badge)
- **Tor Nodes:** Always CRITICAL (even if score 0)

---

## 🤖 ML Models

### Model 1: Basic Classification

Classifies attacks as Bot vs Human based on timing patterns.

```bash
python ml/02_attack_classifier.py
```

**Accuracy:** ~70%  
**Use case:** Quick bot detection

### Model 2: Enhanced Classification

Combines timing patterns WITH threat intelligence features.

```bash
python ml/train_classifier.py
```

**Accuracy:** ~80% (+10% improvement)  
**Features:**
- `time_diff_seconds` (86.4% importance) - Attack timing
- `abuse_score` (2.3% importance) - AbuseIPDB score
- `total_reports` (9.2% importance) - How many times reported
- `is_tor` (2.1% importance) - Tor exit node flag

**Result:** Threat intelligence adds ~10% accuracy!

---

## 📈 Data Pipeline

### Full Flow

```
Raw Honeypot Logs
    ↓
    src/clean_logs.py (filter noise)
    ↓
Cleaned Logs: data/cleaned_attacks.jsonl
    ↓
    src/enrichment_worker.py (add threat data)
    ↓
Enriched Logs: data/enriched_real_attacks.jsonl
    ↓
    Dashboard (display with threat badges)
```

### Running the Pipeline

#### Automatic (Daemon)
```bash
docker exec honeypot-ml python src/enrichment_daemon.py
# Runs every 60 seconds automatically
```

#### Manual
```bash
# Clean raw logs
docker exec honeypot-main python src/clean_logs.py

# Enrich cleaned logs
docker exec honeypot-ml python src/enrichment_worker.py

# Dashboard reloads automatically
```

---

## 🧪 Testing

### Run All Tests
```bash
python ml/test_all_ml.py
```

### Run Individual Tests
```bash
# Threat Intelligence only
python ml/test_threat_intel.py

# Generate synthetic data
python ml/generate_synthetic_data.py

# Check statistics
python ml/check_stats.py
```

### Test Coverage

| Component | Tests | Status |
|-----------|-------|--------|
| Threat Intelligence | 5 | ✅ |
| Data Pipeline | 2 | ✅ |
| Classification | 3 | ✅ |
| Enhanced ML | 4 | ✅ |
| **Total** | **14** | **✅** |

---

## 📝 Example Usage

### Get Threat Data for an IP

```python
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).parent / 'models'))
from threat_intelligence import ThreatIntelligence

ti = ThreatIntelligence(api_key="your_key")

# Check if Tor
result = ti.get_threat_data("185.220.101.1")
print(f"Is Tor: {result['threat_data']['isTor']}")  # True
print(f"Abuse Score: {result['threat_data']['abuseConfidenceScore']}")  # 100
```

### Enrich Attack Data

```python
attack = {
    "timestamp": "2026-03-21T13:00:00Z",
    "source_ip": "203.0.113.45",
    "port": 22,
    "service": "ssh",
    "event_type": "SSH_LOGIN",
    "details": "username=root password=..."
}

enriched = ti.enrich_attack(attack)
print(enriched['threat_intelligence'])
# {
#     "status": "success",
#     "threat_data": {...},
#     "last_updated": "2026-03-21T..."
# }
```

---

## 🐛 Troubleshooting

### "No API key found"
```bash
# Set in .env file
ABUSEIPDB_API_KEY=your_key_here

# Or manually in code
ti = ThreatIntelligence(api_key="abc123...")
```

### "Rate limit exceeded"
The module automatically handles this:
- Stops making API calls
- Returns cached data
- Logs warning

No action needed!

### "Private IP returned as public"
This is intentional - private IPs are filtered to save quota.

Valid private IP ranges:
- `192.168.0.0 - 192.168.255.255`
- `10.0.0.0 - 10.255.255.255`
- `172.16.0.0 - 172.31.255.255`
- `127.0.0.0 - 127.255.255.255` (localhost)

---

## 📚 Learning Resources

### Threat Intelligence APIs
- [AbuseIPDB Docs](https://docs.abuseipdb.com/)
- [VirusTotal API](https://developers.virustotal.com/)
- [IPQualityScore](https://www.ipqualityscore.com/)

### Machine Learning
- [Scikit-learn Classification](https://scikit-learn.org/stable/modules/classification.html)
- [Feature Engineering](https://www.feature-engine.readthedocs.io/)
- [ML Best Practices](https://github.com/microsoft/ML-For-Beginners)

### HoneyPot Project
- See `ML_TEST_RESULTS.md` for detailed test results
- See `src/enrichment_daemon.py` for pipeline automation
- See `src/dashboard.py` for dashboard integration

---

## 🎯 Next Steps

### Short-term
- [x] Threat intelligence working
- [x] Data pipeline complete
- [x] Bot/Human classification trained
- [x] Enhanced ML with threat features
- [x] Comprehensive testing

### Medium-term
- [ ] Real-time threat alerts
- [ ] Additional threat APIs (VirusTotal, IPQualityScore)
- [ ] Geolocation analysis
- [ ] Anomaly detection

### Long-term
- [ ] Deep learning models
- [ ] Automated response system
- [ ] SIEM integration
- [ ] Honeypot optimization

---

## 📄 License

Educational security research tool. See main README.

## 👨‍💻 Author

Built with Mentor Mode learning approach - Understanding concepts > Copy-paste code

---

**Last Updated:** March 21, 2026  
**Status:** ✅ Production Ready
