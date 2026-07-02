# 🛡️ Windows Service & Process Monitoring Agent

<p align="center">
  <img src="assets/banner.png" alt="WSPM Agent Banner" width="800"/>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.12+-blue?style=for-the-badge&logo=python"/>
  <img src="https://img.shields.io/badge/Platform-Windows%2010%2F11-0078d4?style=for-the-badge&logo=windows"/>
  <img src="https://img.shields.io/badge/License-MIT-green?style=for-the-badge"/>
  <img src="https://img.shields.io/badge/Category-Cybersecurity-red?style=for-the-badge&logo=hackthebox"/>
</p>

---

## 📌 Overview

**Windows Service & Process Monitoring Agent (WSPM Agent)** is a professional-grade Blue Team cybersecurity tool built in Python. It continuously monitors Windows processes and services to detect malicious, unauthorized, and abnormal activity in real time.

Designed for **SOC analysts, Blue Team defenders, cybersecurity students**, and anyone who wants to understand what is running on their Windows system.

---

## 🎯 Objectives

- Detect malware, cryptominers, RATs, and backdoors by process behaviour
- Identify LOLBin abuse (mshta, certutil, regsvr32, rundll32)
- Detect suspicious parent-child process chains (Office → PowerShell)
- Monitor Windows services for tampering and rogue binaries
- Audit startup persistence locations (Registry Run keys, Startup folder)
- Classify all threats using MITRE ATT&CK techniques
- Generate professional PDF, CSV, Excel, JSON, and TXT security reports

---

## ✨ Features

### 🔍 Detection Capabilities
| Feature | Description |
|---|---|
| Real-Time Process Monitoring | Enumerate PID, name, path, CPU, RAM, username, signature |
| Parent-Child Analysis | Detect Office → PowerShell, mshta → cmd, and 15+ attack chains |
| Service Monitoring | Detect rogue, disabled-security, and temp-folder services |
| Startup Audit | Scan Registry Run keys and startup folders for persistence |
| Unauthorized Detection | Whitelist/blacklist enforcement + path-based + hash-based detection |
| Behaviour Detection | High CPU (cryptominer), unsigned processes, encoded commands |

### 🖥️ Dashboard
| Feature | Description |
|---|---|
| Dark Theme GUI | Professional dark Tkinter dashboard |
| Real-Time Auto Refresh | Every 5 seconds (configurable) |
| Live Metric Cards | Process count, service count, CPU%, RAM%, alert counts |
| Color-Coded Alerts | Critical=Red, High=Orange, Medium=Yellow, Low=Blue |
| Search & Filter | Filter by process name, service name, severity |
| Notification Popups | Floating alerts for Critical/High threats |
| Process Tree Viewer | Full system process ancestry tree |
| Threat History | All historical alerts from database |

### 📊 Reports
| Format | Contents |
|---|---|
| PDF | Charts, alerts, MITRE mapping, recommendations |
| Excel | Multi-sheet: Alerts, Processes, Services, Summary |
| CSV | Flat alert export |
| JSON | Full structured data dump |
| TXT | Human-readable text summary |

---

## 🏗️ Architecture

```
WindowsServiceProcessMonitoringAgent/
│
├── main.py                    ← Entry point & MonitoringAgent controller
├── requirements.txt
├── README.md
│
├── config/
│   ├── settings.json          ← Global settings (intervals, GUI, thresholds)
│   ├── whitelist.json         ← Trusted processes & services
│   ├── blacklist.json         ← Known malicious processes, hashes, keywords
│   └── detection_rules.json  ← 18 configurable detection rules
│
├── modules/
│   ├── process_monitor.py     ← MODULE 1: Real-time process scanner
│   ├── process_tree.py        ← MODULE 2: Parent-child relationship analyzer
│   ├── service_monitor.py     ← MODULE 3: Windows service enumerator
│   ├── startup_audit.py       ← MODULE 4: Startup persistence auditor
│   ├── unauthorized_detector.py ← MODULE 5: Unauthorized process detector
│   ├── alert_manager.py       ← MODULE 6: Alert engine (Critical/High/Medium/Low)
│   ├── logger.py              ← MODULE 7: JSON + TXT + CSV logging
│   ├── database_manager.py    ← MODULE 8: SQLite persistence layer
│   ├── report_generator.py    ← MODULE 9: PDF/CSV/Excel/JSON/TXT reports
│   ├── scheduler.py           ← Background task scheduler
│   ├── dashboard.py           ← Dark theme Tkinter GUI
│   └── utils.py               ← Shared utilities (hash, signature, system info)
│
├── database/
│   └── monitoring.db          ← SQLite database (auto-created)
├── logs/                      ← Session logs (JSON + TXT + CSV)
├── reports/                   ← Generated reports
└── exports/                   ← Manual data exports
```

---

## 🔧 Tech Stack

| Library | Purpose |
|---|---|
| `psutil` | Process & system metrics |
| `pywin32` | Windows service API (win32service) |
| `wmi` | Windows Management Instrumentation |
| `tkinter` | Dark theme GUI dashboard |
| `sqlite3` | Local database persistence |
| `reportlab` | PDF report generation |
| `pandas` | Excel/CSV data handling |
| `matplotlib` | Charts (pie, bar, timeline) |
| `openpyxl` | Excel file writing |
| `colorama` | Terminal color output |

---

## 📦 Installation

### Prerequisites
- Windows 10 or Windows 11
- Python 3.12 or higher
- Visual C++ Redistributable (for pywin32)

### Step 1 — Clone the repository
```bash
git clone https://github.com/RiddhiManani/Windows-Service-Process-Monitoring-Agent.git
cd WindowsServiceProcessMonitoringAgent
```

### Step 2 — Create a virtual environment
```bash
python -m venv venv
venv\Scripts\activate
```

### Step 3 — Install dependencies
```bash
pip install -r requirements.txt
```

### Step 4 — Run as Administrator
```bash
# Right-click Command Prompt → "Run as Administrator"
python main.py
```

> ⚠️ **Administrator privileges are required** for full process and service visibility.
> Without them, some system processes will show "Access Denied".

---

## 🚀 How to Run

```bash
# Quick launch (standard user — limited visibility)
python main.py

# Full launch (recommended — Administrator)
# Open CMD as Administrator, then:
python main.py
```

The dashboard will open automatically. The first scan runs in the background immediately.

---

## 🎮 Dashboard Usage

| Button | Action |
|---|---|
| ⚡ Quick Scan | Immediately run a full scan cycle |
| 🔍 Deep Scan | Run with signature + hash verification |
| ⏸ Pause | Suspend background monitoring |
| ▶ Resume | Resume monitoring |
| 📄 Report | Generate all reports at once |
| ⚙ Settings | Open settings / whitelist / blacklist editor |
| Auto Refresh ✓ | Toggle automatic 5-second refresh |

---

## 🛡️ Detection Rules

The agent ships with **18 built-in detection rules** in `config/detection_rules.json`:

| Rule ID | Name | MITRE |
|---|---|---|
| RULE-001 | Office Spawning Shell | T1566 |
| RULE-002 | PowerShell Spawning CMD | T1059.001 |
| RULE-003 | MSHTA Spawning Shell | T1218.005 |
| RULE-004 | Explorer Spawning Script | T1059 |
| RULE-005 | Process from Temp | T1036 |
| RULE-006 | Process from Downloads | T1204 |
| RULE-007 | Process from Recycle Bin | T1036.005 |
| RULE-008 | Unsigned Process | T1553.002 |
| RULE-009 | Service from Temp Folder | T1543.003 |
| RULE-010 | New Startup Entry | T1547.001 |
| RULE-011 | WMIC Spawning Process | T1047 |
| RULE-012 | Certutil Downloading Files | T1140 |
| RULE-013 | Regsvr32 Abuse | T1218.010 |
| RULE-014 | High CPU Usage (Cryptominer) | T1496 |
| RULE-015 | Disabled Security Service | T1562.001 |
| RULE-016 | RunDLL32 Abuse | T1218.011 |
| RULE-017 | Process from Public Folder | T1036.005 |
| RULE-018 | Script Running from AppData | T1036 |

---

## 📁 Configuration Files

### `config/settings.json`
Controls scan intervals, GUI theme, alert thresholds, and log settings.

### `config/whitelist.json`
Trusted process names, paths, and service names that suppress low-priority alerts.

### `config/blacklist.json`
Known malicious process names (mimikatz, meterpreter, xmrig, etc.), keywords, and file hashes.

### `config/detection_rules.json`
All detection rules — enable/disable individually, adjust severity levels, add custom parent-child chains.

---

## 📊 Report Contents

Each generated report includes:

- Project name, scan date, system information
- Total processes and services scanned
- Threat summary (Critical / High / Medium / Low counts)
- Top suspicious processes
- Alert timeline
- MITRE ATT&CK technique mapping
- Severity distribution chart
- All critical alerts with details
- Actionable recommendations

---

## 🔮 Future Scope

- [ ] Network connection monitoring (netstat integration)
- [ ] Email alert notifications (SMTP)
- [ ] Remote agent deployment (multi-host monitoring)
- [ ] YARA rule integration for memory scanning
- [ ] Threat intelligence feed integration (VirusTotal API)
- [ ] Windows Event Log correlation
- [ ] EDR-style process memory inspection
- [ ] Web-based dashboard alternative (Flask/FastAPI)
- [ ] SIEM integration (Splunk, ELK)
- [ ] Automated incident response playbooks

---

## ⚠️ Disclaimer

This tool is developed for **educational, research, and defensive security purposes only**.
Use responsibly and only on systems you own or have explicit written permission to monitor.
The authors are not responsible for any misuse of this software.

---

## 📄 License

This project is licensed under the **MIT License** — see the [LICENSE](LICENSE) file for details.

---

## 👤 Author

**Security Research Team**
Built for cybersecurity portfolio, academic submission, and Blue Team operations.


