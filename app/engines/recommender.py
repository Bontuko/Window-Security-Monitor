import json
import os
import re

# 1) Load KB
_KB_PATH = os.path.join(os.path.dirname(__file__), "../../data/knowledge_base.json")
try:
    with open(_KB_PATH, encoding="utf-8") as f:
        KB = json.load(f).get("rules", [])
except Exception as e:
    raise RuntimeError(f"Failed to load knowledge_base.json: {e}")

def generate_explanation_and_recommendation(entry):
    """
    Returns (explanation, recommendation) for a given scan entry.
    Tries to match a KB rule; if none match, falls back to severity logic.
    """
    module     = entry.get("Module", "")
    name       = entry.get("name", "")
    raw_exp    = entry.get("explanation", "")
    status     = entry.get("status", "")
    severity   = entry.get("severity", "").lower()

    # 2) Try each rule in order
    for rule in KB:
        m = rule.get("match", {})

        # a) module match
        if "module" in m and m["module"] != module:
            continue

        # b) namePattern
        np = m.get("namePattern")
        if np and not re.search(np, name):
            continue

        # c) explanationPattern
        ep = m.get("explanationPattern")
        if ep and not re.search(ep, raw_exp, re.IGNORECASE):
            continue

        # matched: render templates
        params = {
            "value":       status,
            "name":        name,
            **rule.get("parameters", {})
        }

        tpl_exp = rule["templates"].get("explanation", "")
        tpl_rec = rule["templates"].get("recommendation", "")

        try:
            explanation    = tpl_exp.format(**params)
            recommendation = tpl_rec.format(**params)
        except KeyError:
            # if your template expects a param that's missing
            explanation    = tpl_exp
            recommendation = tpl_rec

        return explanation, recommendation

    # 3) Fallback by severity
    base = raw_exp or "No explanation provided."
    if severity == "high":
        return base, "Disable or investigate immediately"
    if severity == "medium":
        return base, "Research further and monitor closely"
    if severity == "low":
        return base, "No action needed unless new issues appear"
    return base, "Manual review recommended"
