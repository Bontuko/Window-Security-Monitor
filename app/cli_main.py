#!/usr/bin/env python3
# main.py

import argparse
import sys
from datetime import datetime

from app.monitors.service_module    import scan_services
from app.monitors.task_module       import scan_tasks
from app.monitors.wmi_module        import scan_wmi
from app.monitors.startup_module    import scan_startup
from app.monitors.system_module     import scan_system

from app.engines.severity        import classify
from app.engines.explainer      import generate_explanation_and_recommendation
from app.reporting.exporter import export_all_logs, export_severity_summary


MODULE_FUNCTIONS = {
    "services": scan_services,
    "tasks":    scan_tasks,
    "wmi":      scan_wmi,
    "startup":  scan_startup,
    "system":   scan_system,
}


def collect_entries(func):
    """
    Run one scan function, normalize its output into a list of dicts,
    and timestamp each entry.
    """
    raw = func()
    entries = []
    for item in raw:
        entry = dict(item)
        entry.setdefault("timestamp", datetime.now().isoformat())
        entry.setdefault("path",       item.get("path", ""))
        entry.setdefault("start_mode", item.get("start_mode", ""))
        entries.append(entry)
    return entries


def main():
    parser = argparse.ArgumentParser(
        description="ProcSentinel CLI – scan Windows modules and export reports"
    )
    parser.add_argument(
        "-m", "--module",
        choices=list(MODULE_FUNCTIONS.keys()) + ["all"],
        default="all",
        help="Which module to scan (default: all)"
    )
    parser.add_argument(
        "-o", "--output",
        default="exported_logs",
        help="Folder to write CSV and PDF reports into"
    )
    args = parser.parse_args()

    to_run = MODULE_FUNCTIONS.keys() if args.module == "all" else [args.module]
    all_entries = []

    for name in to_run:
        func = MODULE_FUNCTIONS[name]
        entries = collect_entries(func)
        for e in entries:
            e["Module"] = name.capitalize()

            # classify severity & generate explanation
            sev, expl = classify(e)
            e["severity_summary"] = sev
            e["explanation"]       = expl

            # *** ADD THIS LINE to satisfy export_severity_summary ***
            e["severity"] = sev

            # generate recommendation
            _, rec = generate_explanation_and_recommendation(e)
            e["recommendation"]    = rec

            all_entries.append(e)

    if not all_entries:
        print("No findings to export.")
        sys.exit(0)

    # Export detailed logs
    export_all_logs(all_entries, folder_name=args.output)

    # Export severity summary CSV (now sees e["severity"])
    export_severity_summary(all_entries, folder_name=args.output)

    print(f"Exported {len(all_entries)} entries to '{args.output}/'.")
    sys.exit(0)


if __name__ == "__main__":
    main()
