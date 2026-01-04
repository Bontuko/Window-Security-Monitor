"""
ProcSentinel Monitors Package

Contains all system monitoring modules:
- service_module: Windows Services
- task_module: Scheduled Tasks
- wmi_module: WMI Event Bindings
- startup_module: Startup Items
- system_module: System Health & Security
- network_module: Network Connections
- process_module: Running Processes
- registry_module: Registry Persistence
"""

from app.monitors.service_module import scan_services
from app.monitors.task_module import scan_tasks
from app.monitors.wmi_module import scan_wmi
from app.monitors.startup_module import scan_startup
from app.monitors.system_module import scan_system
from app.monitors.network_module import scan_network
from app.monitors.process_module import scan_processes
from app.monitors.registry_module import scan_registry

__all__ = [
    'scan_services',
    'scan_tasks',
    'scan_wmi',
    'scan_startup',
    'scan_system',
    'scan_network',
    'scan_processes',
    'scan_registry',
]
