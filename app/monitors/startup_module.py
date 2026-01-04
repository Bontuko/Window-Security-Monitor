# core/startup_module.py

import pythoncom
import wmi
from datetime import datetime
from pythoncom import com_error

def scan_startup():
    """
    Scan Windows startup commands under root\\CIMV2.
    Returns a list of dicts with keys: name, path, status, start_mode, timestamp.
    """
    pythoncom.CoInitialize()
    results = []
    try:
        cimv2 = wmi.WMI(namespace=r"root\CIMV2")
        for cmd in cimv2.Win32_StartupCommand():
            results.append({
                "name":       cmd.Name,
                "path":       cmd.Command,
                "status":     "",
                "start_mode": cmd.User,
                "timestamp":  datetime.now().isoformat()
            })
    except com_error as ce:
        print(f"scan_startup: WMI COM error: {ce}")
    except Exception as e:
        print(f"scan_startup: unexpected error: {e}")
    return results


class StartupModule:
    """
    Class‐based wrapper for scan_startup(), enabling:
        from core.startup_module import StartupModule
    """
    def __init__(self):
        pass

    def run(self):
        return scan_startup()
