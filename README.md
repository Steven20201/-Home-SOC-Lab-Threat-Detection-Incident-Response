# 🛡️ Home SOC Lab — Threat Detection & Incident Response

> A personal Security Operations Centre (SOC) home lab built to simulate real-world threat detection, log analysis, alert triage, and incident response workflows using industry-standard tools.

---

## 📌 Overview

This project documents the setup and operation of a home SOC lab environment. The goal is to develop hands-on experience with SIEM platforms, network traffic analysis, and attacker simulation — directly aligned with the day-to-day responsibilities of a SOC Analyst.

**Core focus areas:**
- Real-time log ingestion and correlation
- Alert detection and triage
- Network traffic analysis
- Incident response simulation
- MITRE ATT&CK technique mapping

---

## 🧰 Tools & Technologies

| Category | Tool | Purpose |
|---|---|---|
| SIEM | Wazuh | Log ingestion, correlation, alerting |
| SIEM | Splunk | Dashboard monitoring, SPL queries |
| Network Analysis | Wireshark | Packet capture and traffic inspection |
| Threat Simulation | TryHackMe | Attacker technique practice (Level 1) |
| Automation | Python | Log parsing and alert enrichment scripts |
| Framework | MITRE ATT&CK | Mapping detections to known TTPs |

---

## 🏗️ Lab Architecture

```
┌─────────────────────────────────────────────────────┐
│                    Home SOC Lab                     │
│                                                     │
│  ┌─────────────┐        ┌──────────────────────┐   │
│  │  Attacker   │──────▶ │   Target Machine     │   │
│  │  (Kali /    │        │   (Windows / Linux)  │   │
│  │  TryHackMe) │        └──────────┬───────────┘   │
│  └─────────────┘                   │ logs           │
│                                    ▼                │
│                         ┌──────────────────┐        │
│                         │   Wazuh Agent    │        │
│                         └────────┬─────────┘        │
│                                  │ forwards          │
│                                  ▼                  │
│                    ┌─────────────────────────┐      │
│                    │    Wazuh Manager/SIEM   │      │
│                    │    + Splunk Indexer     │      │
│                    └─────────────────────────┘      │
│                                  │                  │
│                                  ▼                  │
│                    ┌─────────────────────────┐      │
│                    │   Analyst Workstation   │      │
│                    │  Wireshark | Dashboards │      │
│                    └─────────────────────────┘      │
└─────────────────────────────────────────────────────┘
```

---

## ⚙️ Setup & Configuration

### 1. Wazuh SIEM
- Deployed Wazuh Manager on a local Ubuntu VM
- Installed Wazuh Agents on Windows and Linux endpoints
- Configured custom detection rules for:
  - Failed login attempts (brute force)
  - Privilege escalation attempts
  - Suspicious process execution
  - File integrity monitoring (FIM) alerts

### 2. Splunk
- Ingested Wazuh alerts into Splunk via syslog forwarding
- Built custom dashboards for:
  - Login activity monitoring
  - Top alert sources by host
  - Timeline of security events
- Practised SPL (Search Processing Language) queries for threat hunting

### 3. Wireshark
- Captured live traffic during simulated attacks
- Analysed protocols: TCP, UDP, DNS, HTTP, ICMP
- Identified indicators of compromise (IOCs):
  - Port scan signatures (SYN floods)
  - Brute force patterns
  - Unusual DNS queries

---

## 🎯 Simulated Attack Scenarios

| Scenario | Technique | MITRE ATT&CK |
|---|---|---|
| SSH Brute Force | Credential Stuffing | T1110.001 |
| Port Scanning | Network Discovery | T1046 |
| Privilege Escalation | Sudo abuse | T1548.003 |
| Suspicious Process | Unexpected child process | T1059 |
| File Modification | Tampering with logs | T1070.002 |

---

## 🐍 Python Automation

Located in `/scripts/`:

- **`log_parser.py`** — Parses raw Wazuh JSON alerts and extracts key fields (timestamp, rule ID, severity, source IP)
- **`alert_enricher.py`** — Enriches alerts with geolocation data using IP lookup
- **`brute_force_detector.py`** — Flags IPs with more than N failed logins within a time window

```python
# Example: brute force detection logic
from collections import defaultdict

def detect_brute_force(logs, threshold=5, window_seconds=60):
    attempts = defaultdict(list)
    flagged = []

    for log in logs:
        ip = log['source_ip']
        timestamp = log['timestamp']
        attempts[ip].append(timestamp)

        recent = [t for t in attempts[ip] if timestamp - t <= window_seconds]
        if len(recent) >= threshold:
            flagged.append({'ip': ip, 'attempts': len(recent)})

    return flagged
```

---

## 📊 Sample Detections

### Wazuh Alert — Brute Force Detected
```json
{
  "rule": {
    "id": "5763",
    "description": "Multiple authentication failures",
    "level": 10
  },
  "agent": { "name": "windows-endpoint" },
  "data": {
    "srcip": "192.168.1.105",
    "failed_attempts": 12
  },
  "timestamp": "2024-11-15T08:32:14.000Z"
}
```

---

## 📚 What I Learned

- How to deploy and configure a SIEM from scratch in a home environment
- Writing and tuning detection rules to reduce false positives
- Reading and interpreting raw packet captures to identify attack patterns
- Mapping observed behaviour to MITRE ATT&CK tactics and techniques
- Automating repetitive SOC tasks with Python scripting

---

## 🏅 Certifications & Training

- **CompTIA Security+** — Score: 769/900
- **TryHackMe** — SOC Level 1 path (in progress)
- **A1 German** — Language study in progress (targeting Germany-based roles)

---

## 🗺️ Roadmap

- [ ] Add Elastic Stack (ELK) as an alternative SIEM setup
- [ ] Integrate threat intelligence feeds (AlienVault OTX)
- [ ] Build a phishing simulation and email analysis module
- [ ] Document a full incident response playbook
- [ ] Add Zeek for network security monitoring

---

## 🔗 Connect

- **LinkedIn:** [Khant Zaw Hein](https://www.linkedin.com/in/khant-zaw-hein-ba0173197/)
- **TryHackMe:** *(add your profile URL here)*

---

> ⚠️ *This lab is for educational purposes only. All attack simulations are conducted in an isolated, controlled environment.*
