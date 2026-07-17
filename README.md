# SOC IP Intelligence Panel

A lightweight Threat Intelligence tool built for SOC Analysts to quickly investigate IP addresses using multiple reputation sources.

The application performs bulk IP reputation analysis by integrating **VirusTotal** and **AbuseIPDB**, providing a single verdict to speed up IOC investigation during incident response, phishing investigations, and threat hunting.

---

## Features

- Bulk IP scanning
- VirusTotal Integration
- AbuseIPDB Integration
- Unified Threat Verdict
- Automatic IOC enrichment
- Bulk investigation support
- Copy investigation results
- Lightweight PHP application
- No database required
- Dark SOC dashboard

---

## Screenshot

> Add a screenshot of the dashboard here.

---

# Tech Stack

- PHP
- HTML5
- CSS3
- JavaScript
- VirusTotal API v3
- AbuseIPDB API

---

# Folder Structure

```
SOC-IP-Intelligence-Panel/
│
├── index.php              # Dashboard
├── scan_single.php        # Threat Intelligence Engine
└── README.md
```

---

# How It Works

1. Paste one or more IP addresses.
2. Click **Run Scan**.
3. The application

- Queries VirusTotal
- Queries AbuseIPDB
- Correlates both results
- Calculates a unified verdict
- Displays analyst-friendly information
- Allows copying investigation output

---

# Sample Output

```
IP
45.155.205.233

Verdict
Malicious

VirusTotal
M:18 S:4 H:76

VirusTotal Status
Malicious

Abuse Confidence
100

ISP
M247 Europe SRL

Country
RO

Reports
214
```

---

# Installation

Clone repository

```bash
git clone https://github.com/yourusername/SOC-IP-Intelligence-Panel.git
```

Move the project into your web server.

Example (XAMPP)

```
htdocs/
    SOC-IP-Intelligence-Panel/
```

Open

```
http://localhost/SOC-IP-Intelligence-Panel/
```

---

# API Configuration

Open

```
scan_single.php
```

Replace

```php
$VT_API_KEY = "YOUR_VT_API_KEY";
$ABUSE_API_KEY = "YOUR_ABUSEIPDB_API_KEY";
```

with your own API keys.

---

# APIs Used

## VirusTotal

Provides

- Detection ratio
- Community reputation
- Threat classification

Documentation

https://developers.virustotal.com/reference

---

## AbuseIPDB

Provides

- Abuse Confidence Score
- ISP Information
- Country
- Total Abuse Reports

Documentation

https://docs.abuseipdb.com/

---

# Verdict Logic

## Malicious

Any of the following:

- VirusTotal malicious detections > 5
- Abuse Confidence Score ≥ 75

---

## Suspicious

Any of the following:

- VirusTotal malicious detections > 0
- VirusTotal suspicious detections > 0
- Abuse Confidence Score between 25–74

---

## Clean

- No VirusTotal detections
- Abuse Confidence Score below 25

---

# Output Fields

| Field | Description |
|--------|-------------|
| IP | Investigated IP |
| Verdict | Final analyst verdict |
| VT Score | VirusTotal detection statistics |
| VT Status | VirusTotal reputation |
| Abuse Score | AbuseIPDB confidence score |
| ISP | Internet Service Provider |
| Country | Country Code |
| Reports | Number of Abuse Reports |

---

# SOC Use Cases

- IOC Enrichment
- Threat Hunting
- Phishing Investigation
- Malware Analysis
- Incident Response
- Firewall Rule Validation
- Threat Intelligence
- Security Operations Center (SOC)
- IP Reputation Analysis

---

# Current Limitations

- Public API rate limits
- No authentication
- No database
- No historical scan storage
- No PDF reports
- No CSV export

---

# Roadmap

- PDF Report Export
- CSV Export
- Excel Export
- GeoIP Map
- WHOIS Lookup
- ASN Lookup
- Passive DNS
- AlienVault OTX Integration
- GreyNoise Integration
- ThreatFox Integration
- Shodan Integration
- URLhaus Integration
- Batch Processing Queue
- Analyst Notes
- Scan History
- IOC Dashboard
- Authentication
- REST API

---

# Security Notice

- Never expose your API keys.
- Store credentials securely using environment variables or server-side configuration.
- Do not commit API keys to public repositories.

---

# License

MIT License

---

# Author

**Sanjay Kotabagi**

SOC Analyst

GitHub

https://github.com/SanjayKotabagi

LinkedIn

https://linkedin.com/in/sanjaykotabagi

---

# Contributing

Contributions are welcome.

Feel free to submit pull requests for new intelligence sources, UI improvements, or additional analyst features.

---

# Star the Repository

If this project helps your SOC workflow or threat hunting activities, consider giving the repository a ⭐.
