# SOC Sentinel — Linux Authentication Threat Detection Lab

> A Python-based security monitoring and detection engineering lab for identifying suspicious Linux authentication activity.

![Python](https://img.shields.io/badge/Python-3.13-blue)
![Security](https://img.shields.io/badge/Focus-SOC%20%7C%20Detection%20Engineering-red)
![Testing](https://img.shields.io/badge/Tests-3%20Passed-success)
![License](https://img.shields.io/badge/License-MIT-green)

---

## Overview

SOC Sentinel is a defensive cybersecurity project that analyzes Linux authentication logs and identifies patterns associated with suspicious account activity.

The project simulates a Security Operations Center (SOC) detection workflow:

**Log Collection → Parsing → Detection Rules → Alert Generation → Investigation**

The goal is to demonstrate practical skills in security monitoring, log analysis, detection engineering, Python development, and incident investigation.

---

## Security Use Cases

The detection engine identifies several authentication-based threats, including:

- SSH brute-force activity
- Repeated authentication failures followed by a successful login
- Multiple source IP addresses targeting the same account
- Authentication activity involving privileged accounts

---

## Detection Rules

| Rule | Detection | Severity |
|------|-----------|----------|
| AUTH-001 | SSH Brute Force | HIGH |
| AUTH-002 | Successful Login Following Repeated Failures | HIGH |
| AUTH-003 | Multiple Sources Targeting Account | MEDIUM |
| AUTH-004 | Privileged Account Authentication Activity | MEDIUM |

---

## Example Detection

Example simulated activity:

```text
Source: 203.0.113.50
Target: admin

8 failed authentication attempts
1 successful authentication

Detection:
AUTH-002 - Successful Login Following Repeated Failures

Severity:
HIGH

linux-auth-threat-detection-lab/
│
├── data/
│   └── auth.log
│
├── detections/
│   └── detection-rules.md
│
├── reports/
│   └── incident-report.md
│
├── screenshots/
│   ├── detection-output.png
│   └── tests-passed.png
│
├── src/
│   ├── __init__.py
│   ├── main.py
│   ├── parser.py
│   └── detector.py
│
├── tests/
│   └── test_detector.py
│
├── .gitignore
├── LICENSE
├── README.md
└── requirements.txt

# Technologies
Python
Linux authentication log analysis
Detection engineering
SOC alert triage
Incident investigation
Pytest
GitHub
