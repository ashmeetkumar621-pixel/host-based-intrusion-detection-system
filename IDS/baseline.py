import json
import os
import time
from datetime import datetime
from typing import Dict, Any
from config import BASELINE_FILE, EXCLUDE_PATHS, INCLUDE_PATHS

class BaselineManager:
    def __init__(self):
        self.baseline: Dict[str, Dict[str, Any]] = {}
        self.last_save = 0
    
    def load(self) -> Dict[str, Dict[str, Any]]:
        """Load baseline with error recovery."""
        if os.path.exists(BASELINE_FILE):
            try:
                with open(BASELINE_FILE, 'r') as f:
                    self.baseline = json.load(f)
                print(f"✅ Loaded {len(self.baseline)} files from baseline")
            except json.JSONDecodeError:
                print("⚠️ Corrupted baseline. Starting fresh.")
                self.baseline = {}
        return self.baseline
    
    def save(self):
        """Periodically save baseline."""
        if time.time() - self.last_save > 60:  # Throttle saves
            try:
                with open(BASELINE_FILE, 'w') as f:
                    json.dump(self.baseline, f, indent=2)
                self.last_save = time.time()
            except Exception as e:
                print(f"❌ Baseline save failed: {e}")
    
    def should_monitor(self, filepath: str) -> bool:
        """Apply include/exclude rules."""
        relpath = os.path.relpath(filepath, 'D:\\')
        
        # Quick excludes
        if any(excl in filepath.lower() for excl in EXCLUDE_PATHS):
            return False
        
        # Specific includes (if set)
        if INCLUDE_PATHS and not any(path in filepath for path in INCLUDE_PATHS):
            return False
            
        return True
    
    def update_file(self, relpath: str, hashes: Dict[str, str]):
        """Update baseline for a file."""
        self.baseline[relpath] = {
            "hashes": hashes,
            "last_modified": datetime.now().isoformat()
        }
