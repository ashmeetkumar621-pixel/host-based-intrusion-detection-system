import json
import os
from datetime import datetime
from typing import Dict, Any
from config import MALWARE_HASHES_FILE, SUSPICIOUS_EXTENSIONS
from hashing import calculate_multi_hash

class DetectionEngine:
    def __init__(self):
        self.malware_hashes: set = set()
        self.load_signatures()
    
    def load_signatures(self):
        """Load malware hashes from file."""
        if os.path.exists(MALWARE_HASHES_FILE):
            try:
                with open(MALWARE_HASHES_FILE, 'r') as f:
                    data = json.load(f)
                    self.malware_hashes = set(data.get("sha256", []) + data.get("md5", []))
                print(f"✅ Loaded {len(self.malware_hashes)} malware signatures")
            except Exception as e:
                print(f"⚠️ Failed to load signatures: {e}")
                self.malware_hashes = set()
        else:
            print(f"ℹ️ No signature file found: {MALWARE_HASHES_FILE}")
    
    def analyze_file(self, filepath: str, action: str, baseline: Dict[str, Any]) -> Dict[str, Any]:
        """Full file analysis with proper conditional logic."""
        relpath = os.path.relpath(filepath, 'D:\\')
        hashes = calculate_multi_hash(filepath)
        severity = "INFO"
        reason = "MONITORED"
        
        # 1. Signature detection (highest priority)
        malware_detected = False
        for hash_type, hash_val in hashes.items():
            if (isinstance(hash_val, str) and 
                hash_val in self.malware_hashes and 
                hash_val not in ["FILE_TOO_LARGE", "PERMISSION_DENIED", "ERROR:"]):
                severity = "CRITICAL"
                reason = f"MALWARE_SIGNATURE_MATCH_{hash_type.upper()}"
                malware_detected = True
                break
        
        # 2. Suspicious extension (if no malware signature)
        if not malware_detected:
            if any(filepath.lower().endswith(ext) for ext in SUSPICIOUS_EXTENSIONS):
                severity = "HIGH"
                reason = "SUSPICIOUS_EXTENSION"
        
        # 3. Integrity breach (if no higher priority detection)
        if severity == "INFO" and action == "Modified" and relpath in baseline:
            old_hashes = baseline[relpath]["hashes"]
            if hashes.get("sha256") != old_hashes.get("sha256"):
                severity = "MEDIUM"
                reason = "INTEGRITY_BREACH"
        
        # 4. New file creation
        if action == "Created" and severity == "INFO":
            severity = "LOW"
            reason = "NEW_FILE_CREATED"
        
        return {
            "path": relpath,
            "action": action,
            "hashes": hashes,
            "severity": severity,
            "reason": reason,
            "timestamp": datetime.now().isoformat()
        }
    
    def get_signature_stats(self) -> Dict[str, int]:
        """Get statistics about loaded signatures."""
        return {
            "total_signatures": len(self.malware_hashes),
            "sha256_count": sum(1 for h in self.malware_hashes if len(h) == 64),
            "md5_count": sum(1 for h in self.malware_hashes if len(h) == 32)
        }
