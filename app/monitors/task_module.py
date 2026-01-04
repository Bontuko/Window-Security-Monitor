#!/usr/bin/env python3
# core/task_module.py

import subprocess
import csv
import io

def scan_tasks():
    """
    Query Scheduled Tasks via schtasks.
    Returns a list of dicts, each containing:
      - name:   task name
      - status: task status (Ready, Running, Disabled, etc.)
      - path:   the command or executable the task runs
    """
    cmd    = ["schtasks", "/query", "/v", "/fo", "csv"]
    output = subprocess.check_output(cmd, text=True, errors="ignore")
    reader = csv.DictReader(io.StringIO(output))
    results = []

    for row in reader:
        name   = row.get("TaskName", "").strip()
        status = row.get("Status", "").strip()
        path   = row.get("Task To Run", "").strip()

        results.append({
            "name":   name,
            "status": status,
            "path":   path
        })

    return results
