import wmi
import os
from .utils import get_file_version

def scan_services():
    c = wmi.WMI()
    services = []
    state_counts = {}

    for service in c.Win32_Service():
        name = service.Name
        display_name = service.DisplayName
        state = service.State
        raw_path = service.PathName

        path = "Not available"
        version = "Unknown"
        if raw_path:
            path = raw_path.strip('"').split(" ")[0]
            version = get_file_version(path) if os.path.exists(path) else "Path not found"

        state_counts[state] = state_counts.get(state, 0) + 1

        services.append({
            "name": name,
            "display_name": display_name,
            "state": state,
            "path": path,
            "version": version
        })

    return services, state_counts
