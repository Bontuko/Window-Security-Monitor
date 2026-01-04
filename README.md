# ProcSentinel

**ProcSentinel** is a powerful Windows security monitoring and threat detection tool. It scans running services, processes, network connections, startup items, registry persistence, and system health to identify potential security risks.

## 🛡️ Features

- **8 Security Modules:** Services, Tasks, WMI, Startup, System, Network, Processes, Registry
- **Security Scoring:** 0-100 score based on detected threats
- **Threat Detection:** Identifies suspicious paths, malware patterns, and persistence mechanisms
- **Modern Dashboard:** Dark-themed UI with real-time threat visualization
- **Risk Classification:** High/Medium/Low severity with actionable recommendations
- **Export Capability:** Save scan results to CSV for reporting

## 📊 Monitored Areas

| Module | What it Checks |
|--------|---------------|
| **Services** | Windows services running from suspicious locations |
| **Tasks** | Scheduled tasks with error states or suspicious commands |
| **WMI** | WMI event bindings (common malware persistence) |
| **Startup** | Boot-time programs and scripts |
| **System** | Defender, Firewall, Disk, Memory, Updates status |
| **Network** | Active connections to suspicious ports |
| **Process** | Running processes from temp folders, high resource usage |
| **Registry** | Persistence keys with script execution |

## 🚀 Quick Start

```bash
# Install dependencies
pip install -r requirements.txt

# Run the application
python run.py
```

## 📋 Requirements

- Python 3.8+
- Windows 10/11
- Administrator privileges (recommended for full scanning)

## 📦 Dependencies

```
psutil>=5.9.0
wmi>=1.5.1
```

## 🔒 Security Checks

The tool detects:
- Services/processes running from `%TEMP%`, `%APPDATA%`, `Downloads`
- Known malware tool names (mimikatz, netcat, etc.)
- PowerShell encoded commands
- WMI persistence mechanisms
- Disabled Windows Defender or Firewall
- Suspicious network connections
- Registry autorun entries with script execution

## 📸 Screenshots

The dashboard displays:
- **Security Score** (0-100) with color-coded status
- **Threat Summary** showing High/Medium/Low counts
- **Module Statistics** with per-module breakdown
- **Results Table** with severity filtering
- **Details Panel** with explanations and recommendations

## 📄 License

Educational project for Windows security monitoring.

## ✍️ Author

Bontu Abera
