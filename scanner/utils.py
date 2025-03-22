import win32api
import os

def safe_cvss_score(value):
    try:
        return float(value)
    except (ValueError, TypeError):
        return 0.0  # Default to 0 if value is invalid or missing

def get_file_version(path):
    try:
        info = win32api.GetFileVersionInfo(path, "\\")
        ms = info['FileVersionMS']
        ls = info['FileVersionLS']
        return f"{win32api.HIWORD(ms)}.{win32api.LOWORD(ms)}.{win32api.HIWORD(ls)}.{win32api.LOWORD(ls)}"
    except Exception:
        return "Unknown"
