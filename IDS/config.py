import os
from typing import List, Dict, Set

# Core Paths
MONITORED_DIRECTORY = 'D:\\'
BASELINE_FILE = 'd_drive_baseline.json'
LOGS_FILE = 'hids_logs.jsonl'

# Performance Tuning
TIME_WINDOW_SECONDS = 5
ANOMALY_THRESHOLD = 10
MAX_FILE_SIZE_MB = 50  # Skip hashing files > 50MB
DEBOUNCE_SECONDS = 1.0
BASELINE_SAVE_INTERVAL = 60

# Monitoring Rules
INCLUDE_PATHS = []  # e.g., ['D:\\Projects', 'D:\\Documents']
EXCLUDE_PATHS = [
    'D:\\Windows', 'D:\\Program Files', 'D:\\$Recycle.Bin',
    'D:\\System Volume Information', 'D:\\pagefile.sys'
]
SUSPICIOUS_EXTENSIONS = {'.exe', '.dll', '.scr', '.bat', '.cmd', '.ps1', '.vbs', '.js', '.locked', '.enc'}

# Malware Signatures (load from external file in production)
MALWARE_HASHES_FILE = 'malware_hashes.json'
