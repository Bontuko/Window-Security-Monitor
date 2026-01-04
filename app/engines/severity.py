# severity_engine.py
"""
Severity classification engine with enhanced detection capabilities.
"""

import json
import os
import re

# Load JSON rules with explicit UTF-8
_RULES_PATH = os.path.join(os.path.dirname(__file__), "../../data/severity_rules.json")

try:
    with open(_RULES_PATH, "r", encoding="utf-8") as f:
        RULES = json.load(f)
except Exception as e:
    print(f"Warning: Could not load severity rules: {e}")
    RULES = {}

# Suspicious path patterns
SUSPICIOUS_PATHS = [
    r"\\temp\\",
    r"\\tmp\\",
    r"\\appdata\\local\\temp",
    r"\\downloads\\",
    r"\\public\\",
    r"\\users\\public",
]

# Suspicious command patterns
SUSPICIOUS_COMMANDS = [
    r"powershell.*-enc",
    r"powershell.*bypass",
    r"cmd\s*/c",
    r"wscript",
    r"cscript",
    r"mshta",
    r"regsvr32.*scrobj",
    r"certutil.*-urlcache",
    r"bitsadmin.*/transfer",
]


def classify(entry):
    """
    Classify a scan entry based on severity rules.
    
    entry dict should have:
      - Module  (e.g. "Services", "Network", "Process")
      - name    (item name)
      - status  (current state/status string)
      - path    (optional, file path)
      
    Returns: (severity, explanation)
    """
    module = entry.get("Module", "")
    name = entry.get("name", "")
    state = entry.get("status", "")
    path = entry.get("path", "")
    
    # Check if entry already has risk_score (from new modules)
    risk_score = entry.get("risk_score", 0)
    if risk_score > 0:
        if risk_score >= 40:
            return "High", f"High-risk item detected: {state}"
        elif risk_score >= 20:
            return "Medium", f"Medium-risk item: {state}"
    
    # ── System / Uptime special case ───────────────────────
    if module == "System" and name == "Uptime":
        cfg = RULES.get("System", {}).get("Uptime", {})
        thr = cfg.get("thresholds", {})
        expls = cfg.get("explanations", {})
        
        try:
            days = int(state.split(" days")[0])
        except:
            days = 0
        
        low_max = thr.get("low", {}).get("maxDays", 7)
        med_max = thr.get("medium", {}).get("maxDays", 30)
        
        if days <= low_max:
            return "Low", expls.get("low", "Uptime is normal.").format(state=state)
        if days <= med_max:
            return "Medium", expls.get("medium", "Consider rebooting.").format(
                state=state, lowMax=low_max
            )
        return "High", expls.get("high", "Reboot recommended.").format(
            state=state, medMax=med_max
        )
    
    # ── Enhanced path-based detection ─────────────────────
    path_lower = path.lower() if path else ""
    
    # Check for suspicious paths
    for pattern in SUSPICIOUS_PATHS:
        if re.search(pattern, path_lower, re.IGNORECASE):
            return "High", f"{module} item '{name}' runs from suspicious location: {path}"
    
    # Check for suspicious commands in path/status
    combined = f"{path_lower} {state.lower()}"
    for pattern in SUSPICIOUS_COMMANDS:
        if re.search(pattern, combined, re.IGNORECASE):
            return "High", f"{module} item '{name}' uses suspicious command pattern."
    
    # ── Module-specific rules from JSON ────────────────────
    mod_cfg = RULES.get(module, {})
    
    for rule_name, rule in mod_cfg.items():
        if rule_name == "default":
            continue
        
        m = rule.get("match", {})
        
        # match stateIn
        if "stateIn" in m and state in m["stateIn"]:
            return rule["severity"], rule.get("explanation", "").format(
                name=name, state=state, path=path
            )
        
        # match stateNot
        if "stateNot" in m and state != m["stateNot"]:
            return rule["severity"], rule.get("explanation", "").format(
                name=name, state=state, path=path
            )
        
        # Services: startMode + state check
        if (module == "Services"
            and m.get("startMode") == entry.get("startMode")
            and state != m.get("stateNot", "")):
            return rule["severity"], rule.get("explanation", "").format(
                name=name, state=state, path=path
            )
        
        # pathContains check
        if "pathContains" in m:
            for pattern in m["pathContains"]:
                if pattern.lower() in path_lower:
                    return rule["severity"], rule.get("explanation", "").format(
                        name=name, state=state, path=path
                    )
    
    # ── Check status for warning indicators ────────────────
    if "⚠️" in state or "DISABLED" in state or "error" in state.lower():
        return "High", f"{module} item '{name}': {state}"
    
    # ── Fallback default ──────────────────────────────────
    default = mod_cfg.get("default", {})
    sev = default.get("severity", "Low")
    expl = default.get("explanation", f"{module} item {name} status: {state}").format(
        name=name, state=state, path=path
    )
    
    return sev, expl
