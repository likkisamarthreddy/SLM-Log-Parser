import os
import json
import re
from typing import Dict, Any

class Anonymizer:
    def __init__(self):
        self.hosts = {}
        self.users = {}
        self.pids = {}
        self.remote_hosts = {}
        
        self._host_counter = 1
        self._user_counter = 1
        self._pid_counter = 1
        self._rhost_counter = 1

    def _get_id(self, mapping: dict, prefix: str, raw_val: str, counter_attr: str) -> str:
        if raw_val not in mapping:
            counter = getattr(self, counter_attr)
            mapping[raw_val] = f"{prefix}_{counter:03d}"
            setattr(self, counter_attr, counter + 1)
        return mapping[raw_val]

    def _get_host(self, val): return self._get_id(self.hosts, "HOST", str(val), "_host_counter")
    def _get_user(self, val): return self._get_id(self.users, "USER", str(val), "_user_counter")
    def _get_pid(self, val): return self._get_id(self.pids, "PID", str(val), "_pid_counter")
    def _get_rhost(self, val): return self._get_id(self.remote_hosts, "REMOTE_HOST", str(val), "_rhost_counter")

    def derive_event_and_enrich(self, message: str, meta: dict) -> str:
        msg_lower = message.lower()
        event = "unknown"
        
        if "session opened" in msg_lower: 
            event = "session_opened"
            m = re.search(r'session opened for user (\S+)', message)
            if m: meta["user"] = m.group(1)
            
        elif "session closed" in msg_lower: 
            event = "session_closed"
            m = re.search(r'session closed for user (\S+)', message)
            if m: meta["user"] = m.group(1)
            
        elif "authentication failure" in msg_lower or "failure; logname=" in msg_lower: 
            event = "authentication_failure"
            
        elif "exited abnormally" in msg_lower: 
            event = "abnormal_exit"
            
        elif "password check failed" in msg_lower:
            event = "authentication_failure"
            
        elif "accepted password" in msg_lower or "accepted publickey" in msg_lower: 
            event = "authentication_success"
            
        elif "disconnected from" in msg_lower: 
            event = "session_closed"
            
        return event

    def anonymize(self, record: Dict[str, Any], raw_line: str) -> Dict[str, Any]:
        out = record.copy()
        
        # Original canonical fields
        hostname = out.get("hostname")
        if hostname:
            out["hostname"] = self._get_host(hostname)
            
        pid = out.get("pid")
        if pid is not None:
            out["pid"] = self._get_pid(pid)
            
        # Extract event BEFORE masking message
        msg = out.get("message", "")
        meta = out.get("metadata", {})
        
        out["event"] = self.derive_event_and_enrich(msg, meta)
        
        # Mask user
        if "user" in meta and meta["user"]:
            meta["user"] = self._get_user(meta["user"])
        if "ruser" in meta and meta["ruser"]:
            meta["ruser"] = self._get_user(meta["ruser"])
            
        # Mask rhost
        if "rhost" in meta and meta["rhost"]:
            meta["rhost"] = self._get_rhost(meta["rhost"])
            
        # Scrape and mask naked IP addresses
        ip_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
        for ip in ip_pattern.findall(msg):
            self._get_rhost(ip)  # Register it in the mapping
            
        # Mask message (replace known entities in reverse length order)
        masked_msg = msg
        replacements = []
        for real, anon in self.users.items():
            if real: replacements.append((real, anon))
        for real, anon in self.hosts.items():
            if real: replacements.append((real, anon))
        for real, anon in self.remote_hosts.items():
            if real: replacements.append((real, anon))
            
        # Sort by length descending to avoid partial matches
        replacements.sort(key=lambda x: -len(x[0]))
        
        for real, anon in replacements:
            masked_msg = re.sub(rf'\b{re.escape(real)}\b', anon, masked_msg)
            
        out["message"] = masked_msg
        
        # Construct masked raw log
        masked_raw = raw_line
        if hostname:
            masked_raw = re.sub(rf'\b{re.escape(hostname)}\b', out["hostname"], masked_raw, count=1)
        if pid:
            masked_raw = re.sub(rf'\[{re.escape(str(pid))}\]', f'[{out["pid"]}]', masked_raw)
            
        for real_u, anon_u in self.users.items():
            if real_u:
                masked_raw = re.sub(rf'\buser\s+{re.escape(real_u)}\b', f'user {anon_u}', masked_raw)
                masked_raw = re.sub(rf'\buser={re.escape(real_u)}\b', f'user={anon_u}', masked_raw)
        for real_r, anon_r in self.remote_hosts.items():
            if real_r:
                masked_raw = re.sub(rf'\brhost={re.escape(real_r)}\b', f'rhost={anon_r}', masked_raw)
                
        out["raw_log"] = raw_line
        out["masked_log"] = masked_raw
        
        return out
        
    def save_mapping(self, path: str):
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            json.dump({
                "hosts": self.hosts,
                "users": self.users,
                "pids": self.pids,
                "remote_hosts": self.remote_hosts
            }, f, indent=2)
