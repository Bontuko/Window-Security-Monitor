#!/usr/bin/env python3
"""
Network Monitor - Detect suspicious network activity and connections.
"""

import psutil
from datetime import datetime

# Suspicious ports commonly used by malware
SUSPICIOUS_PORTS = {
    4444: "Metasploit default",
    5555: "Android Debug Bridge (potential backdoor)",
    6666: "IRC backdoor",
    6667: "IRC backdoor",
    1337: "Common backdoor port",
    31337: "Back Orifice",
    12345: "NetBus",
    27374: "SubSeven",
    20: "FTP Data (unusual if outbound)",
    23: "Telnet (insecure)",
    445: "SMB (potential lateral movement)",
    3389: "RDP (check if expected)",
    5900: "VNC",
    8080: "HTTP Proxy (potential C2)",
    9001: "Tor default",
    9050: "Tor SOCKS",
}

# Known legitimate system processes that commonly have network activity
KNOWN_SYSTEM_PROCESSES = {
    "system", "svchost.exe", "services.exe", "lsass.exe",
    "wininit.exe", "csrss.exe", "smss.exe", "explorer.exe",
    "searchindexer.exe", "spoolsv.exe", "taskhost.exe"
}


def scan_network():
    """
    Scan active network connections for suspicious activity.
    Returns a list of dicts with connection details.
    """
    results = []
    
    try:
        connections = psutil.net_connections(kind='inet')
    except (psutil.AccessDenied, PermissionError):
        return [{
            "name": "Network Scan",
            "status": "Access Denied - Run as Administrator",
            "path": "",
            "risk_score": 0,
            "timestamp": datetime.now().isoformat()
        }]
    
    # Track unique connections
    seen = set()
    
    for conn in connections:
        try:
            # Get process info
            if conn.pid:
                try:
                    proc = psutil.Process(conn.pid)
                    proc_name = proc.name()
                    proc_path = proc.exe() if proc.exe() else ""
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    proc_name = f"PID:{conn.pid}"
                    proc_path = ""
            else:
                proc_name = "Unknown"
                proc_path = ""
            
            # Get connection details
            local_addr = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "N/A"
            remote_addr = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "N/A"
            remote_port = conn.raddr.port if conn.raddr else 0
            
            # Create unique key
            key = (proc_name, local_addr, remote_addr, conn.status)
            if key in seen:
                continue
            seen.add(key)
            
            # Determine risk level
            risk_score = 0
            risk_reasons = []
            
            # Check for suspicious ports
            if remote_port in SUSPICIOUS_PORTS:
                risk_score += 40
                risk_reasons.append(f"Suspicious port: {SUSPICIOUS_PORTS[remote_port]}")
            
            # Check for external connections from unusual processes
            if conn.raddr and conn.status == 'ESTABLISHED':
                if proc_name.lower() not in KNOWN_SYSTEM_PROCESSES:
                    # External connection from non-system process
                    remote_ip = conn.raddr.ip
                    if not remote_ip.startswith(('127.', '192.168.', '10.', '172.')):
                        risk_score += 20
                        risk_reasons.append("External connection")
            
            # Check for listening services
            if conn.status == 'LISTEN':
                if conn.laddr.port < 1024 and proc_name.lower() not in KNOWN_SYSTEM_PROCESSES:
                    risk_score += 30
                    risk_reasons.append("Non-system process listening on privileged port")
                elif conn.laddr.port in SUSPICIOUS_PORTS:
                    risk_score += 50
                    risk_reasons.append(f"Listening on suspicious port")
            
            status = f"{conn.status} | Local: {local_addr} → Remote: {remote_addr}"
            if risk_reasons:
                status += f" | ⚠️ {', '.join(risk_reasons)}"
            
            results.append({
                "name": proc_name,
                "status": status,
                "path": proc_path,
                "risk_score": risk_score,
                "remote_port": remote_port,
                "connection_type": conn.status,
                "timestamp": datetime.now().isoformat()
            })
            
        except Exception:
            continue
    
    # Sort by risk score (highest first)
    results.sort(key=lambda x: x.get("risk_score", 0), reverse=True)
    
    # Limit results to most relevant
    return results[:100]
