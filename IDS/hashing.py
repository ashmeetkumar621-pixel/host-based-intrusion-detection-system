import hashlib
import os
from concurrent.futures import ThreadPoolExecutor
from typing import Dict, Optional, Tuple
from config import MAX_FILE_SIZE_MB

def calculate_multi_hash(filepath: str) -> Dict[str, str]:
    """Calculate SHA256 + MD5 for better detection coverage."""
    hashes = {}
    try:
        file_size = os.path.getsize(filepath)
        if file_size > MAX_FILE_SIZE_MB * 1024 * 1024:
            return {
                "sha256": "FILE_TOO_LARGE", 
                "md5": "FILE_TOO_LARGE", 
                "size": file_size
            }
        
        with open(filepath, 'rb') as f:
            sha256 = hashlib.sha256()
            md5 = hashlib.md5()
            while chunk := f.read(4096):
                sha256.update(chunk)
                md5.update(chunk)
            hashes["sha256"] = sha256.hexdigest()
            hashes["md5"] = md5.hexdigest()
            hashes["size"] = file_size
        return hashes
    except PermissionError:
        return {"sha256": "PERMISSION_DENIED", "md5": "PERMISSION_DENIED", "size": 0}
    except Exception as e:
        return {"sha256": f"ERROR:{str(e)}", "md5": f"ERROR:{str(e)}", "size": 0}

def hash_files_async(filepaths: list) -> Dict[str, Dict[str, str]]:
    """Async hash multiple files using thread pool."""
    results = {}
    with ThreadPoolExecutor(max_workers=4) as executor:
        future_to_path = {
            executor.submit(calculate_multi_hash, path): path 
            for path in filepaths
        }
        for future in future_to_path:
            path = future_to_path[future]
            try:
                results[path] = future.result()
            except Exception as e:
                results[path] = {"sha256": f"HASH_ERROR:{str(e)}", "md5": f"HASH_ERROR:{str(e)}"}
    return results
