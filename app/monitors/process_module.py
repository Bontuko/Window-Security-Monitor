#!/usr/bin/env python3
"""
Process Monitor - Detect suspicious running processes.
"""

import psutil
import os
from datetime import datetime

# Suspicious paths where malware often runs from
SUSPICIOUS_PATHS = [
    "\\temp\\",
    "\\tmp\\",
    "\\appdata\\local\\temp\\",
    "\\downloads\\",
    "\\public\\",
    "\\programdata\\",
    "\\users\\public\\",
]

# Suspicious process names commonly used by malware
SUSPICIOUS_NAMES = {
    "mimikatz": "Credential dumping tool",
    "lazagne": "Password recovery tool",
    "procdump": "Process dumping (potential credential theft)",
    "psexec": "Remote execution tool",
    "netcat": "Network utility (potential backdoor)",
    "nc.exe": "Netcat",
    "ncat.exe": "Nmap Netcat",
    "powershell_ise": "PowerShell ISE (check for suspicious scripts)",
    "wmic": "WMI Command (check context)",
    "certutil": "Certificate utility (often abused for downloads)",
    "bitsadmin": "BITS Admin (often abused for downloads)",
    "mshta": "HTML Application host (script execution)",
    "regsvr32": "COM registration (can run scripts)",
    "rundll32": "DLL execution (check arguments)",
    "cscript": "Script host",
    "wscript": "Script host",
}

# Known Windows system processes (whitelist)
SYSTEM_PROCESSES = {
    "system", "registry", "smss.exe", "csrss.exe", "wininit.exe",
    "services.exe", "lsass.exe", "svchost.exe", "fontdrvhost.exe",
    "dwm.exe", "sihost.exe", "taskhostw.exe", "explorer.exe",
    "shellexperiencehost.exe", "searchui.exe", "runtimebroker.exe",
    "applicationframehost.exe", "systemsettings.exe", "settingsynchost.exe",
    "conhost.exe", "dllhost.exe", "ctfmon.exe", "searchindexer.exe",
    "securityhealthservice.exe", "securityhealthsystray.exe",
    "spoolsv.exe", "audiodg.exe", "wmiprvse.exe",
}


def scan_processes():
    """
    Scan running processes for suspicious indicators.
    Returns a list of dicts with process details and risk assessment.
    """
    results = []
    
    for proc in psutil.process_iter(['pid', 'name', 'exe', 'username', 'cpu_percent', 'memory_percent', 'create_time']):
        try:
            info = proc.info
            proc_name = info['name'] or "Unknown"
            proc_path = info['exe'] or ""
            proc_user = info['username'] or ""
            
            risk_score = 0
            risk_reasons = []
            
            # Skip system idle process
            if info['pid'] == 0:
                continue
            
            name_lower = proc_name.lower()
            path_lower = proc_path.lower() if proc_path else ""
            
            # Check for suspicious process names
            for susp_name, description in SUSPICIOUS_NAMES.items():
                if susp_name in name_lower:
                    risk_score += 50
                    risk_reasons.append(f"Suspicious tool: {description}")
                    break
            
            # Check for suspicious paths
            for susp_path in SUSPICIOUS_PATHS:
                if susp_path in path_lower:
                    risk_score += 30
                    risk_reasons.append(f"Running from suspicious location")
                    break
            
            # Check for high resource usage
            cpu = info.get('cpu_percent', 0) or 0
            mem = info.get('memory_percent', 0) or 0
            
            if cpu > 80:
                risk_score += 15
                risk_reasons.append(f"High CPU: {cpu:.1f}%")
            
            if mem > 50:
                risk_score += 10
                risk_reasons.append(f"High Memory: {mem:.1f}%")
            
            # Check for processes without a path (potentially injected)
            if not proc_path and name_lower not in SYSTEM_PROCESSES:
                risk_score += 25
                risk_reasons.append("No executable path (potential injection)")
            
            # Check for non-system processes running as SYSTEM
            if "system" in proc_user.lower() and name_lower not in SYSTEM_PROCESSES:
                risk_score += 20
                risk_reasons.append("Non-standard process running as SYSTEM")
            
            # Calculate running time
            create_time = info.get('create_time', 0)
            if create_time:
                runtime = datetime.now().timestamp() - create_time
                runtime_str = f"{int(runtime // 3600)}h {int((runtime % 3600) // 60)}m"
            else:
                runtime_str = "Unknown"
            
            status = f"CPU: {cpu:.1f}% | MEM: {mem:.1f}% | Runtime: {runtime_str}"
            if risk_reasons:
                status += f" | ⚠️ {', '.join(risk_reasons)}"
            
            results.append({
                "name": proc_name,
                "status": status,
                "path": proc_path,
                "user": proc_user,
                "pid": info['pid'],
                "risk_score": risk_score,
                "cpu_percent": cpu,
                "memory_percent": mem,
                "timestamp": datetime.now().isoformat()
            })
            
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue
        except Exception:
            continue
    
    # Sort by risk score (highest first)
    results.sort(key=lambda x: x.get("risk_score", 0), reverse=True)
    
    return results[:150]
