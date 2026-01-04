#!/usr/bin/env python3
# core/service_module.py

import wmi

def scan_services():
    """
    Query all Windows services via WMI.
    Returns a list of dicts, each containing:
      - name:       the service name
      - status:     current state (Running, Stopped, etc.)
      - path:       executable path for the service
      - startMode:  start mode (Auto, Manual, Disabled)
    """
    client = wmi.WMI()
    results = []

    for svc in client.Win32_Service():
        results.append({
            "name":      svc.Name,
            "status":    svc.State,
            "path":      svc.PathName or "",
            "startMode": svc.StartMode
        })

    return results
