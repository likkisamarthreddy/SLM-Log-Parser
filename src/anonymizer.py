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
        self.ports = {}
        
        self._host_counter = 1
        self._user_counter = 1
        self._pid_counter = 1
        self._rhost_counter = 1
        self._port_counter = 1

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
    def _get_port(self, val): return self._get_id(self.ports, "PORT", str(val), "_port_counter")

    def derive_event_and_enrich(self, message: str, meta: dict) -> str:
        msg_lower = message.lower()
        event = "unknown"
        
        if "session opened" in msg_lower: 
            event = "session_opened"
            m = re.search(r'session opened for user ([A-Za-z0-9_\-\.]+)', message)
            if m: meta["user"] = m.group(1)
            
        elif "session closed" in msg_lower: 
            event = "session_closed"
            m = re.search(r'session closed for user ([A-Za-z0-9_\-\.]+)', message)
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
            
        elif 'sudo' in message and ('COMMAND=' in message or 'command' in msg_lower):
            event = "sudo_command"
            
        elif 'started' in msg_lower or 'starting' in msg_lower:
            event = "service_started"
            
        elif 'failed' in msg_lower and 'authentication' not in msg_lower:
            event = "service_failed"
            
        elif 'stopped' in msg_lower or 'stopping' in msg_lower:
            event = "service_stopped"
            
        elif 'new session' in msg_lower:
            event = "new_session"
            
        elif 'removed session' in msg_lower or 'session removed' in msg_lower:
            event = "removed_session"
            
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
        local_mapping = {}
        
        orig_user = meta.get("user")
        if orig_user:
            meta["user"] = self._get_user(orig_user)
            local_mapping[orig_user] = meta["user"]
            
        orig_ruser = meta.get("ruser")
        if orig_ruser:
            meta["ruser"] = self._get_user(orig_ruser)
            local_mapping[orig_ruser] = meta["ruser"]
            
        # Mask rhost
        orig_rhost = meta.get("rhost")
        if orig_rhost:
            meta["rhost"] = self._get_rhost(orig_rhost)
            local_mapping[orig_rhost] = meta["rhost"]
            
        # Scrape and mask naked IP addresses
        ip_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
        for ip in ip_pattern.findall(msg):
            local_mapping[ip] = self._get_rhost(ip)
            
        # Scrape and mask port numbers
        port_pattern = re.compile(r'\bport\s+(\d+)\b')
        for port_match in port_pattern.finditer(msg):
            port = port_match.group(1)
            local_mapping[port] = self._get_port(port)
            
        # Build unified mapping and single regex for message
        if local_mapping:
            # Sort by length descending to avoid partial matches
            sorted_keys = sorted(local_mapping.keys(), key=lambda x: -len(str(x)))
            pattern = re.compile(r'\b(' + '|'.join(map(re.escape, sorted_keys)) + r')\b')
            out["message"] = pattern.sub(lambda m: local_mapping[m.group(1)], msg)
        else:
            out["message"] = msg
        
        # Include PIDs and Hostname for the raw_log replacement
        if pid is not None:
            local_mapping[str(pid)] = out["pid"]
        if hostname:
            local_mapping[hostname] = out["hostname"]
            
        if local_mapping:
            sorted_keys = sorted(local_mapping.keys(), key=lambda x: -len(str(x)))
            pattern = re.compile(r'\b(' + '|'.join(map(re.escape, sorted_keys)) + r')\b')
            out["masked_log"] = pattern.sub(lambda m: local_mapping[m.group(1)], raw_line)
        else:
            out["masked_log"] = raw_line
            
        out["raw_log"] = raw_line
        
        return out
        
    def save_mapping(self, path: str):
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            json.dump({
                "hosts": self.hosts,
                "users": self.users,
                "pids": self.pids,
                "remote_hosts": self.remote_hosts,
                "ports": self.ports
            }, f, indent=2)
