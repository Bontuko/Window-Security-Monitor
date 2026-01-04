#!/usr/bin/env python3
"""
System Monitor - Check system security status and health.
"""

import psutil
import socket
import platform
import subprocess
from datetime import datetime


def scan_system():
    """
    Gather system security facts and health status.
    Returns a list of dicts with security-relevant system information.
    """
    results = []
    
    # ========== Uptime ==========
    boot_ts = psutil.boot_time()
    uptime = datetime.now().timestamp() - boot_ts
    days = int(uptime // 86400)
    hours = int((uptime % 86400) // 3600)
    
    risk_score = 0
    if days > 30:
        risk_score = 50
    elif days > 7:
        risk_score = 20
    
    results.append({
        "name": "Uptime",
        "status": f"{days} days, {hours} hours",
        "path": "",
        "risk_score": risk_score,
        "timestamp": datetime.now().isoformat()
    })
    
    # ========== Windows Defender Status ==========
    try:
        result = subprocess.run(
            ["powershell", "-Command", 
             "Get-MpComputerStatus | Select-Object -ExpandProperty RealTimeProtectionEnabled"],
            capture_output=True, text=True, timeout=10
        )
        defender_enabled = result.stdout.strip().lower() == "true"
        
        results.append({
            "name": "Windows Defender",
            "status": "Enabled ✓" if defender_enabled else "⚠️ DISABLED",
            "path": "",
            "risk_score": 0 if defender_enabled else 80,
            "timestamp": datetime.now().isoformat()
        })
    except Exception:
        results.append({
            "name": "Windows Defender",
            "status": "Unable to check status",
            "path": "",
            "risk_score": 10,
            "timestamp": datetime.now().isoformat()
        })
    
    # ========== Firewall Status ==========
    try:
        result = subprocess.run(
            ["powershell", "-Command",
             "(Get-NetFirewallProfile -Profile Domain,Public,Private | Select-Object -ExpandProperty Enabled) -contains $true"],
            capture_output=True, text=True, timeout=10
        )
        firewall_enabled = result.stdout.strip().lower() == "true"
        
        results.append({
            "name": "Windows Firewall",
            "status": "Enabled ✓" if firewall_enabled else "⚠️ DISABLED",
            "path": "",
            "risk_score": 0 if firewall_enabled else 70,
            "timestamp": datetime.now().isoformat()
        })
    except Exception:
        results.append({
            "name": "Windows Firewall",
            "status": "Unable to check status",
            "path": "",
            "risk_score": 10,
            "timestamp": datetime.now().isoformat()
        })
    
    # ========== Disk Space ==========
    try:
        disk = psutil.disk_usage('C:\\')
        percent_used = disk.percent
        free_gb = disk.free / (1024 ** 3)
        
        risk_score = 0
        if percent_used > 95:
            risk_score = 50
            status = f"⚠️ CRITICAL: {percent_used:.1f}% used ({free_gb:.1f} GB free)"
        elif percent_used > 85:
            risk_score = 20
            status = f"Warning: {percent_used:.1f}% used ({free_gb:.1f} GB free)"
        else:
            status = f"{percent_used:.1f}% used ({free_gb:.1f} GB free)"
        
        results.append({
            "name": "Disk Space (C:)",
            "status": status,
            "path": "C:\\",
            "risk_score": risk_score,
            "timestamp": datetime.now().isoformat()
        })
    except Exception:
        pass
    
    # ========== Memory Usage ==========
    try:
        mem = psutil.virtual_memory()
        percent_used = mem.percent
        available_gb = mem.available / (1024 ** 3)
        
        risk_score = 0
        if percent_used > 90:
            risk_score = 40
            status = f"⚠️ High usage: {percent_used:.1f}% ({available_gb:.1f} GB available)"
        elif percent_used > 75:
            risk_score = 15
            status = f"Elevated: {percent_used:.1f}% ({available_gb:.1f} GB available)"
        else:
            status = f"{percent_used:.1f}% used ({available_gb:.1f} GB available)"
        
        results.append({
            "name": "Memory Usage",
            "status": status,
            "path": "",
            "risk_score": risk_score,
            "timestamp": datetime.now().isoformat()
        })
    except Exception:
        pass
    
    # ========== Hostname & OS ==========
    results.append({
        "name": "Hostname",
        "status": socket.gethostname(),
        "path": "",
        "risk_score": 0,
        "timestamp": datetime.now().isoformat()
    })
    
    results.append({
        "name": "OS Version",
        "status": platform.platform(),
        "path": "",
        "risk_score": 0,
        "timestamp": datetime.now().isoformat()
    })
    
    # ========== Pending Updates ==========
    try:
        result = subprocess.run(
            ["powershell", "-Command",
             "(New-Object -ComObject Microsoft.Update.Session).CreateUpdateSearcher().Search('IsInstalled=0').Updates.Count"],
            capture_output=True, text=True, timeout=30
        )
        pending = int(result.stdout.strip()) if result.stdout.strip().isdigit() else 0
        
        risk_score = 0
        if pending > 10:
            risk_score = 40
            status = f"⚠️ {pending} updates pending!"
        elif pending > 0:
            risk_score = 15
            status = f"{pending} updates available"
        else:
            status = "System is up to date ✓"
        
        results.append({
            "name": "Windows Updates",
            "status": status,
            "path": "",
            "risk_score": risk_score,
            "timestamp": datetime.now().isoformat()
        })
    except Exception:
        results.append({
            "name": "Windows Updates",
            "status": "Unable to check",
            "path": "",
            "risk_score": 5,
            "timestamp": datetime.now().isoformat()
        })
    
    return results
