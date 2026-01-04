# core/wmi_module.py

import pythoncom
import wmi
from datetime import datetime

def scan_wmi():
    """
    Attempts to scan WMI event bindings from root\\subscription.
    If access is denied or unavailable, silently falls back to Win32_StartupCommand.
    Returns a list of normalized entries.
    """
    pythoncom.CoInitialize()
    results = []

    # 1) Try elevated namespace for __FilterToConsumerBinding
    try:
        subs = wmi.WMI(namespace=r"root\subscription")
        bindings = subs.instances("__FilterToConsumerBinding")
        for b in bindings:
            flt  = b.Filter
            cons = b.Consumer
            results.append({
                "name":          getattr(flt, "Name", ""),
                "path":          "",
                "status":        "Enabled" if getattr(flt, "Enabled", True) else "Disabled",
                "start_mode":    type(cons).__name__,
                "timestamp":     datetime.now().isoformat(),
                "filter_query":  getattr(flt, "Query", ""),
                "consumer_name": getattr(cons, "Name", "")
            })
        if results:
            return results
    except Exception:
        # Silently ignore COM errors and permission issues
        pass

    # 2) Fallback to Win32_StartupCommand under root\CIMV2
    try:
        cim = wmi.WMI(namespace=r"root\CIMV2")
        cmds = cim.Win32_StartupCommand()
        for cmd in cmds:
            results.append({
                "name":          getattr(cmd, "Name", ""),
                "path":          getattr(cmd, "Command", ""),
                "status":        "",
                "start_mode":    getattr(cmd, "User", ""),
                "timestamp":     datetime.now().isoformat(),
                "filter_query":  "",
                "consumer_name": ""
            })
    except Exception:
        # Silently ignore fallback errors too
        pass

    return results
