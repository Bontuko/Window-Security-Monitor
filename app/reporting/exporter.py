import csv
import os
from datetime import datetime

from app.engines.recommender import generate_explanation_and_recommendation


def export_all_logs(data, folder_name="exported_logs"):
    os.makedirs(folder_name, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = os.path.join(folder_name, f"scan_log_{timestamp}.csv")

    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow([
            "Module", "Name", "Status", "Severity",
            "Date", "Time", "Explanation", "Recommendation"
        ])
        for entry in data:
            exp, rec = generate_explanation_and_recommendation(entry)
            # Parse timestamp and split into date/time
            ts = entry.get("timestamp", "")
            scan_date = ""
            scan_time = ""
            if ts:
                try:
                    dt = datetime.fromisoformat(ts.replace("Z", ""))
                    scan_date = dt.strftime("%Y-%m-%d")
                    scan_time = dt.strftime("%H:%M:%S")
                except:
                    scan_date = ts
                    scan_time = ""
            writer.writerow([
                entry.get("Module", ""),
                entry.get("name", ""),
                entry.get("status", ""),
                entry.get("severity", "unknown"),
                scan_date,
                scan_time,
                exp,
                rec
            ])


def export_severity_summary(data, folder_name="exported_logs"):
    os.makedirs(folder_name, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = os.path.join(folder_name, f"severity_summary_{timestamp}.csv")

    counts = {
        "Low":     sum(e.get("severity", "").lower() == "low" for e in data),
        "Medium":  sum(e.get("severity", "").lower() == "medium" for e in data),
        "High":    sum(e.get("severity", "").lower() == "high" for e in data),
        "Unknown": sum("severity" not in e or e.get("severity", "").strip() == "" for e in data)
    }

    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["Severity Level", "Count"])
        for level, count in counts.items():
            writer.writerow([level, count])
