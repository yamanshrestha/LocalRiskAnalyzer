import psutil
import os
import wmi
from .utils import get_file_version

def get_services_pid_map():
    """Builds a map of PID → service name for active services."""
    c = wmi.WMI()
    service_pids = {}
    for s in c.Win32_Service(State="Running"):
        try:
            pid = int(s.ProcessId)
            service_pids[pid] = s.Name
        except Exception:
            continue
    return service_pids

def scan_processes():
    processes = []
    service_pid_map = get_services_pid_map()

    for proc in psutil.process_iter(['pid', 'name', 'exe']):
        try:
            pid = proc.info['pid']
            name = proc.info['name']
            path = proc.info['exe'] or "Not available"
            version = get_file_version(path) if path != "Not available" and os.path.exists(path) else "Unknown"
            linked_service = service_pid_map.get(pid)

            processes.append({
                "name": name,
                "pid": pid,
                "path": path,
                "version": version,
                "linked_service": linked_service or "None"
            })
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue

    return processes
