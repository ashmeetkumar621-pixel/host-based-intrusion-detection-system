import json
from datetime import datetime
from typing import Dict, Any
from config import LOGS_FILE

def log_event(event: Dict[str, Any]):
    """Log structured event to JSONL file."""
    event["timestamp"] = datetime.now().isoformat()
    try:
        with open(LOGS_FILE, 'a') as f:
            f.write(json.dumps(event) + '\n')
        print(f"[{event['severity']}] {event['reason']}: {event['path']}")
    except Exception as e:
        print(f"LOG ERROR: {e}")
