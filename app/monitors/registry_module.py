#!/usr/bin/env python3
"""
Registry Monitor - Check common malware persistence locations.
"""

import winreg
from datetime import datetime

# Registry locations commonly used for persistence
PERSISTENCE_KEYS = [
    # Current User Run Keys
    (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run", "HKCU Run"),
    (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\RunOnce", "HKCU RunOnce"),
    
    # Local Machine Run Keys
    (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run", "HKLM Run"),
    (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\RunOnce", "HKLM RunOnce"),
    
    # Services
    (winreg.HKEY_LOCAL_MACHINE, r"System\CurrentControlSet\Services", "Services"),
    
    # Winlogon
    (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows NT\CurrentVersion\Winlogon", "Winlogon"),
    
    # Shell Extensions
    (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run", "Startup Approved"),
]

# Known suspicious patterns in registry values
SUSPICIOUS_PATTERNS = [
    ("powershell", "PowerShell command execution"),
    ("cmd /c", "Command line execution"),
    ("wscript", "Script execution"),
    ("cscript", "Script execution"),
    ("mshta", "HTML Application execution"),
    ("regsvr32", "DLL registration/execution"),
    (".vbs", "VBScript file"),
    (".js", "JavaScript file"),
    (".ps1", "PowerShell script"),
    (".bat", "Batch file"),
    ("\\temp\\", "Temp folder execution"),
    ("\\appdata\\local\\temp", "AppData Temp execution"),
    ("downloadedinstaller", "Downloaded installer"),
    ("http://", "URL reference"),
    ("https://", "URL reference"),
    ("-enc", "Encoded PowerShell"),
    ("-encodedcommand", "Encoded PowerShell"),
    ("bypass", "Execution policy bypass"),
]

# Known legitimate entries (whitelist)
KNOWN_LEGITIMATE = {
    "securityhealth", "windows defender", "onedrive", "microsoft",
    "realtek", "nvidia", "intel", "amd", "synaptics", "logitech"
}


def scan_registry():
    """
    Scan common persistence locations in the Windows Registry.
    Returns a list of dicts with registry entry details.
    """
    results = []
    
    for hive, key_path, location_name in PERSISTENCE_KEYS:
        try:
            key = winreg.OpenKey(hive, key_path, 0, winreg.KEY_READ)
        except (FileNotFoundError, PermissionError, OSError):
            continue
        
        try:
            # For regular Run keys, enumerate values
            if "Services" not in location_name:
                i = 0
                while True:
                    try:
                        name, value, _ = winreg.EnumValue(key, i)
                        i += 1
                        
                        entry = analyze_registry_entry(name, value, location_name)
                        results.append(entry)
                        
                    except OSError:
                        break
            else:
                # For Services key, enumerate subkeys and check ImagePath
                i = 0
                while True:
                    try:
                        subkey_name = winreg.EnumKey(key, i)
                        i += 1
                        
                        try:
                            subkey = winreg.OpenKey(key, subkey_name, 0, winreg.KEY_READ)
                            image_path, _ = winreg.QueryValueEx(subkey, "ImagePath")
                            winreg.CloseKey(subkey)
                            
                            entry = analyze_registry_entry(subkey_name, image_path, "Service")
                            entry["name"] = f"[Service] {subkey_name}"
                            results.append(entry)
                            
                        except (FileNotFoundError, OSError):
                            continue
                            
                    except OSError:
                        break
                        
        finally:
            winreg.CloseKey(key)
    
    # Sort by risk score (highest first)
    results.sort(key=lambda x: x.get("risk_score", 0), reverse=True)
    
    return results[:100]


def analyze_registry_entry(name, value, location):
    """
    Analyze a single registry entry for suspicious indicators.
    """
    risk_score = 0
    risk_reasons = []
    
    name_lower = name.lower() if name else ""
    value_lower = str(value).lower() if value else ""
    
    # Check if it's a known legitimate entry
    is_legitimate = any(legit in name_lower or legit in value_lower 
                        for legit in KNOWN_LEGITIMATE)
    
    if not is_legitimate:
        # Check for suspicious patterns
        for pattern, description in SUSPICIOUS_PATTERNS:
            if pattern in value_lower:
                risk_score += 25
                risk_reasons.append(description)
        
        # Unknown entry in sensitive location
        if location in ("HKCU Run", "HKLM Run"):
            if not is_legitimate:
                risk_score += 10
                risk_reasons.append("Unknown autorun entry")
    
    status = f"Location: {location}"
    if risk_reasons:
        status += f" | ⚠️ {', '.join(set(risk_reasons))}"
    else:
        status += " | ✓ Appears legitimate"
    
    return {
        "name": name,
        "status": status,
        "path": str(value),
        "location": location,
        "risk_score": risk_score,
        "timestamp": datetime.now().isoformat()
    }
