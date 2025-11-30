import os
import time
import threading
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from datetime import datetime
from typing import List
from config import *
from baseline import BaselineManager
from detection import DetectionEngine
from logger import log_event

class AnomalyDetector:
    def __init__(self):
        self.recent_events: List[float] = []
        self.lock = threading.Lock()
    
    def record_event(self):
        now = time.time()
        with self.lock:
            self.recent_events = [t for t in self.recent_events if now - t <= TIME_WINDOW_SECONDS]
            self.recent_events.append(now)
        
        if len(self.recent_events) > ANOMALY_THRESHOLD:
            log_event({
                "severity": "HIGH",
                "reason": "ANOMALY_HIGH_ACTIVITY",
                "count": len(self.recent_events),
                "window": TIME_WINDOW_SECONDS
            })

class HIDSHandler(FileSystemEventHandler):
    def __init__(self):
        self.baseline = BaselineManager()
        self.detector = DetectionEngine()
        self.anomaly = AnomalyDetector()
        self.last_hashed = {}  # Debouncing
        
    def on_created(self, event):
        if not event.is_directory:
            time.sleep(DEBOUNCE_SECONDS)
            self.process_event(event.src_path, "Created")
    
    def on_modified(self, event):
        if not event.is_directory:
            time.sleep(DEBOUNCE_SECONDS)
            self.process_event(event.src_path, "Modified")
    
    def on_deleted(self, event):
        if not event.is_directory and self.baseline.should_monitor(event.src_path):
            relpath = os.path.relpath(event.src_path, MONITORED_DIRECTORY)
            if relpath in self.baseline.baseline:
                del self.baseline.baseline[relpath]
            log_event({"action": "Deleted", "path": relpath, "severity": "INFO"})
    
    def process_event(self, filepath: str, action: str):
        if not self.baseline.should_monitor(filepath):
            return
            
        self.anomaly.record_event()
        analysis = self.detector.analyze_file(filepath, action, self.baseline.baseline)
        log_event(analysis)
        
        # Update baseline for non-malicious files
        if analysis["severity"] != "CRITICAL":
            self.baseline.update_file(analysis["path"], analysis["hashes"])

def main():
    if not os.path.isdir(MONITORED_DIRECTORY):
        print(f"❌ Directory not found: {MONITORED_DIRECTORY}")
        return
    
    baseline = BaselineManager()
    baseline.load()
    
    handler = HIDSHandler()
    observer = Observer()
    observer.schedule(handler, MONITORED_DIRECTORY, recursive=True)
    observer.start()
    
    print("🚀 ADVANCED HIDS v2.0 - Real-time monitoring active")
    print(f"📁 Monitoring: {MONITORED_DIRECTORY}")
    print(f"⚠️  Logs: {LOGS_FILE} | Baseline: {BASELINE_FILE}")
    
    try:
        while True:
            time.sleep(BASELINE_SAVE_INTERVAL)
            handler.baseline.save()
    except KeyboardInterrupt:
        observer.stop()
        handler.baseline.save()
        print("✅ HIDS stopped gracefully")

if __name__ == "__main__":
    main()
