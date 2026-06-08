"""
Universal Dynamic Log Parser v3.0
==================================
Format-agnostic log parser with auto-detection, self-healing on format drift,
canonical output schema, streaming I/O, optional LLM-powered format discovery,
and multi-line entry support.

Fixed in v3 (from v2 review):
    1. Streaming I/O — file is never loaded into RAM. Uses generators end-to-end.
       parse_file_streaming() writes NDJSON on the fly for 10GB+ files.
    2. Line counter — manual counter, no enumerate/iterator coupling.
    3. Multi-line / self-healing interaction — continuation detection is disabled
       when consecutive_failures > 0 so it cannot block format drift detection.
    4. Results not held in RAM — core logic is a generator (_parse_iter). The
       list-returning parse_file() is a convenience wrapper for small files.
    5. No lookahead consumption — failure buffer IS the re-detection sample.
       No items are consumed from the main iterator during self-healing.
    6. Proper test suite with golden samples.
    7. apache_error regex splits module:level correctly.
    8. failed_lines stat tracks lines flushed as fallback on mid-stream recovery.
    9. LLM bridge — calls ollama-compatible API for unknown formats.
"""

import os
import re
import sys
import gzip
import bz2
import json
import argparse
import urllib.request
import urllib.error
from typing import Optional, Dict, List, Any, Tuple, Iterator, IO, Generator


# ---------------------------------------------------------------------------
# Severity normalization
# ---------------------------------------------------------------------------

SEVERITY_MAP = {
    "fatal": "CRITICAL", "emerg": "CRITICAL", "emergency": "CRITICAL",
    "alert": "CRITICAL", "crit": "CRITICAL", "critical": "CRITICAL",
    "severe": "CRITICAL", "panic": "CRITICAL",
    "error": "ERROR", "err": "ERROR", "fail": "ERROR", "failure": "ERROR",
    "warning": "WARN", "warn": "WARN",
    "notice": "INFO", "info": "INFO", "information": "INFO",
    "debug": "DEBUG", "trace": "DEBUG", "verbose": "DEBUG",
}

RFC5424_SEVERITY = {
    0: "CRITICAL", 1: "CRITICAL", 2: "CRITICAL",
    3: "ERROR", 4: "WARN", 5: "INFO", 6: "INFO", 7: "DEBUG",
}


def normalize_severity(raw: Optional[str]) -> Optional[str]:
    if raw is None:
        return None
    cleaned = raw.lower().strip("[]() ")
    return SEVERITY_MAP.get(cleaned, "UNKNOWN")


def severity_from_priority(priority_str: str) -> Optional[str]:
    try:
        return RFC5424_SEVERITY.get(int(priority_str) % 8)
    except (ValueError, TypeError):
        return None


# ---------------------------------------------------------------------------
# Timestamp detection (restricted to first 60 chars)
# ---------------------------------------------------------------------------

TIMESTAMP_PATTERNS = [
    (re.compile(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:[+-]\d{2}:\d{2}|Z)'), "iso8601_tz"),
    (re.compile(r'\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?'), "iso8601"),
    (re.compile(r'[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}'), "bsd_syslog"),
    (re.compile(r'\[\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2}\s+[+-]\d{4}\]'), "clf"),
    (re.compile(r'\d{2}/\d{2}/\d{4}\s+\d{1,2}:\d{2}:\d{2}(?:\s+[AP]M)?'), "windows"),
    (re.compile(r'^\d{10}(?:\.\d+)?'), "epoch"),
    (re.compile(r'\d{4}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2}'), "generic_datetime"),
]

_TS_SEARCH_LIMIT = 60


def extract_timestamp(line: str) -> Optional[Tuple[str, str]]:
    region = line[:_TS_SEARCH_LIMIT]
    for pat, name in TIMESTAMP_PATTERNS:
        m = pat.search(region)
        if m:
            return m.group(0), name
    return None


def line_starts_new_event(line: str) -> bool:
    return extract_timestamp(line) is not None


# Patterns that indicate a line is a continuation of the previous event
# (stack traces, wrapped messages, etc.) rather than a new log event.
_CONTINUATION_PATTERN = re.compile(
    r'^(?:'
    r'\s+|'                        # indented (leading whitespace)
    r'\s*at\s+|'                    # Java stack frame
    r'\s*Caused by:|'               # Java chained exception
    r'\s*\.\.\.|'                    # Python traceback elision
    r'\s*File\s+"|'                 # Python traceback frame
    r'\s*Traceback|'                # Python traceback header
    r'\s*\||'                       # pipe-continued lines
    r'\s*#\d+|'                     # C/C++ backtrace (#0, #1, ...)
    r'\s*---'                       # separator lines
    r')'
)


def is_continuation_line(line: str) -> bool:
    """True if a line looks structurally like a continuation of the previous event."""
    if line_starts_new_event(line):
        return False
    return bool(_CONTINUATION_PATTERN.match(line))


# ---------------------------------------------------------------------------
# LogFormat
# ---------------------------------------------------------------------------

class LogFormat:
    def __init__(self, name: str, pattern: re.Pattern, fields: List[str],
                 priority: int = 0, description: str = "",
                 field_map: Optional[Dict[str, str]] = None,
                 severity_field: Optional[str] = None,
                 severity_from_priority_field: Optional[str] = None):
        self.name = name
        self.pattern = pattern
        self.fields = fields
        self.priority = priority
        self.description = description
        self.field_map = field_map or {}
        self.severity_field = severity_field
        self.severity_from_priority_field = severity_from_priority_field

    def try_parse(self, line: str) -> Optional[Dict[str, Any]]:
        m = self.pattern.match(line.strip())
        return m.groupdict() if m else None

    def score(self, sample_lines: List[str]) -> float:
        if not sample_lines:
            return 0.0
        return sum(1 for l in sample_lines if self.try_parse(l) is not None) / len(sample_lines)

    def to_canonical(self, raw: Dict[str, Any], line_num: int) -> Dict[str, Any]:
        canonical = {
            "line_number": line_num,
            "timestamp": None,
            "severity": None,
            "hostname": None,
            "process": None,
            "component": None,
            "pid": None,
            "message": "",
            "_format": self.name,
            "metadata": {},
        }

        canonical_keys = {"timestamp", "hostname", "process", "component", "pid", "message"}

        for key, val in raw.items():
            if val is None:
                continue
            if key == "pid":
                try:
                    val = int(val)
                except (ValueError, TypeError):
                    pass
                canonical["pid"] = val
            elif key in self.field_map:
                canonical[self.field_map[key]] = val
            elif key in canonical_keys:
                canonical[key] = val
            else:
                canonical["metadata"][key] = val

        # Severity
        if self.severity_from_priority_field and self.severity_from_priority_field in raw:
            canonical["severity"] = severity_from_priority(raw[self.severity_from_priority_field])
        elif self.severity_field and self.severity_field in raw:
            canonical["severity"] = normalize_severity(raw[self.severity_field])

        # Synthesize message from extras if missing (e.g. Apache access logs)
        if not canonical["message"] and canonical["metadata"]:
            parts = [f"{k}={v}" for k, v in canonical["metadata"].items() if v is not None]
            canonical["message"] = " ".join(parts)
            
        # Optional KV extraction for syslog-style messages
        if canonical["message"]:
            msg = canonical["message"]
            kv_matches = list(KV_PATTERN.finditer(msg))
            if kv_matches:
                for m in kv_matches:
                    k = m.group(1)
                    v = m.group(2)
                    if (v.startswith('"') and v.endswith('"')) or (v.startswith("'") and v.endswith("'")):
                        v = v[1:-1]
                    # Try to parse integers
                    if v.isdigit():
                        v = int(v)
                    canonical["metadata"][k] = v
                # Clean up the message by removing all KV pairs and trailing punctuation
                clean_msg = KV_PATTERN.sub('', msg).strip(' ;:,')
                # If there are multiple spaces left over, squish them
                import re as _re
                canonical["message"] = _re.sub(r'\s+', ' ', clean_msg).strip()

        return canonical


# ---------------------------------------------------------------------------
# Built-in format library
# ---------------------------------------------------------------------------

BUILTIN_FORMATS = [
    LogFormat(
        name="bsd_syslog",
        pattern=re.compile(
            r'^(?P<timestamp>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+'
            r'(?P<hostname>\S+)\s+'
            r'(?P<process>[A-Za-z0-9_\-\.]+)(?:\((?P<component>[^\)]+)\))?(?:\[(?P<pid>\d+)\])?:\s*'
            r'(?P<message>.+)$'
        ),
        fields=["timestamp", "hostname", "process", "component", "pid", "message"],
        priority=10,
        description="Standard BSD syslog",
    ),

    LogFormat(
        name="rfc5424_syslog",
        pattern=re.compile(
            r'^<(?P<priority>\d+)>'
            r'(?P<version>\d+)\s+'
            r'(?P<timestamp>\S+)\s+'
            r'(?P<host>\S+)\s+'
            r'(?P<app>\S+)\s+'
            r'(?P<procid>\S+)\s+'
            r'(?P<msgid>\S+)\s*'
            r'(?P<structured_data>(?:\[.*?\])*|-)\s*'
            r'(?P<message>.*)$'
        ),
        fields=["priority", "version", "timestamp", "host", "app",
                "procid", "msgid", "structured_data", "message"],
        priority=15,
        description="RFC 5424 structured syslog",
        field_map={"app": "process"},
        severity_from_priority_field="priority",
    ),

    LogFormat(
        name="apache_combined",
        pattern=re.compile(
            r'^(?P<remote_host>\S+)\s+'
            r'(?P<ident>\S+)\s+'
            r'(?P<user>\S+)\s+'
            r'\[(?P<timestamp>[^\]]+)\]\s+'
            r'"(?P<method>\S+)\s+(?P<path>\S+)\s+(?P<protocol>[^"]+)"\s+'
            r'(?P<status>\d{3})\s+'
            r'(?P<bytes>\S+)'
            r'(?:\s+"(?P<referrer>[^"]*)")?\s*'
            r'(?:"(?P<user_agent>[^"]*)")?'
        ),
        fields=["remote_host", "ident", "user", "timestamp", "method",
                "path", "protocol", "status", "bytes", "referrer", "user_agent"],
        priority=12,
        description="Apache/Nginx combined access log",
        field_map={"remote_host": "host"},
    ),

    # Apache error log — split [module:level] into separate groups
    LogFormat(
        name="apache_error",
        pattern=re.compile(
            r'^\[(?P<timestamp>[^\]]+)\]\s+'
            r'\[(?:(?P<module>[^:\]]+):)?(?P<level>[^\]]*)\]\s+'
            r'\[pid\s+(?P<pid>\d+)[^\]]*\]\s*'
            r'(?:\[client\s+(?P<client>[^\]]+)\]\s*)?'
            r'(?P<message>.+)$'
        ),
        fields=["timestamp", "module", "level", "pid", "client", "message"],
        priority=11,
        description="Apache/Nginx error log",
        severity_field="level",
    ),

    LogFormat(
        name="windows_event",
        pattern=re.compile(
            r'^(?P<date>\d{2}/\d{2}/\d{4})\s+'
            r'(?P<time>\d{1,2}:\d{2}:\d{2}\s+[AP]M)\s+'
            r'(?P<source>\S+)\s+'
            r'(?P<event_id>\d+)\s+'
            r'(?P<level>\S+)\s+'
            r'(?P<message>.+)$'
        ),
        fields=["date", "time", "source", "event_id", "level", "message"],
        priority=8,
        description="Windows Event Log export",
        field_map={"source": "process"},
        severity_field="level",
    ),

    LogFormat(
        name="hdfs_log",
        pattern=re.compile(
            r'^(?P<timestamp>\d{6}\s+\d{6})\s+'
            r'(?P<pid>\d+)\s+'
            r'(?P<level>[A-Z]+)\s+'
            r'(?P<component>[^:]+):\s*'
            r'(?P<message>.+)$'
        ),
        fields=["timestamp", "pid", "level", "component", "message"],
        priority=9,
        description="HDFS/Hadoop log format",
        field_map={"component": "process"},
        severity_field="level",
    ),

    LogFormat(
        name="bgl_log",
        pattern=re.compile(
            r'^(?P<label>\S+)\s+'
            r'(?P<timestamp>\d{10}(?:\.\d+)?)\s+'
            r'(?P<date>\d{4}\.\d{2}\.\d{2})\s+'
            r'(?P<node>[^\s]+)\s+'
            r'(?P<time>\S+)\s+'
            r'(?P<node_rep>\S+)\s+'
            r'(?P<type>\S+)\s+'
            r'(?P<component>\S+)\s+'
            r'(?P<level>\S+)\s*'
            r'(?P<message>.*)$'
        ),
        fields=["label", "timestamp", "date", "node", "time",
                "node_rep", "type", "component", "level", "message"],
        priority=7,
        description="BGL (Blue Gene/L) supercomputer log",
        field_map={"node": "host", "component": "process"},
        severity_field="level",
    ),

    LogFormat(
        name="generic_iso",
        pattern=re.compile(
            r'^(?P<timestamp>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:[+-]\d{2}:\d{2}|Z)?)\s+'
            r'(?:\[?(?P<level>[A-Z]{2,8})\]?\s+)?'
            r'(?:(?P<component>[A-Za-z0-9_\.\-]+)(?:\[(?P<pid>\d+)\])?[:\s]+)?'
            r'(?P<message>.+)$'
        ),
        fields=["timestamp", "level", "component", "pid", "message"],
        priority=5,
        description="Generic ISO-8601 timestamped log",
        field_map={"component": "process"},
        severity_field="level",
    ),

    # Key=Value — lowest priority, deprioritized in detect_format()
    LogFormat(
        name="key_value",
        pattern=re.compile(
            r'^(?P<full_line>(?:[a-zA-Z_][a-zA-Z0-9_\-\.]*=(?:"[^"]*"|\S+)\s*){2,}.*)$'
        ),
        fields=["full_line"],
        priority=1,
        description="Key=value structured log lines",
    ),
]


# ---------------------------------------------------------------------------
# JSON helpers
# ---------------------------------------------------------------------------

def try_parse_json_line(line: str) -> Optional[Dict[str, Any]]:
    stripped = line.strip()
    if stripped.startswith('{'):
        try:
            return json.loads(stripped)
        except (json.JSONDecodeError, ValueError):
            return None
    return None


_JSON_FIELD_ALIASES = {
    "timestamp": ["timestamp", "time", "ts", "@timestamp", "datetime", "date"],
    "severity":  ["level", "severity", "loglevel", "log_level", "lvl", "priority"],
    "hostname":  ["host", "hostname", "server", "node", "machine"],
    "process":   ["process", "service", "app", "application", "logger", "source", "class"],
    "component": ["component", "module"],
    "message":   ["message", "msg", "text", "body", "log", "description"],
}
_JSON_REVERSE_MAP: Dict[str, str] = {}
for _cn, _aliases in _JSON_FIELD_ALIASES.items():
    for _alias in _aliases:
        _JSON_REVERSE_MAP[_alias.lower()] = _cn


def json_to_canonical(raw: Dict[str, Any], line_num: int) -> Dict[str, Any]:
    canonical = {
        "line_number": line_num, "timestamp": None, "severity": None,
        "hostname": None, "process": None, "component": None, "pid": None, "message": "",
        "_format": "json", "metadata": {},
    }
    for key, val in raw.items():
        target = _JSON_REVERSE_MAP.get(key.lower())
        if target:
            if target == "severity":
                canonical["severity"] = normalize_severity(str(val))
            else:
                canonical[target] = val
        else:
            canonical["metadata"][key] = val
    if canonical["message"] is None:
        canonical["message"] = ""
    elif not isinstance(canonical["message"], str):
        canonical["message"] = str(canonical["message"])
    return canonical


# ---------------------------------------------------------------------------
# KV extractor
# ---------------------------------------------------------------------------

KV_PATTERN = re.compile(r'(?<![^\s;])([a-zA-Z_][a-zA-Z0-9_\-\.]*)=("(?:[^"\\]|\\.)*"|\'(?:[^\'\\]|\\.)*\'|[^\s\)\]]*)')

def extract_key_values(line: str) -> Dict[str, str]:
    result = {}
    for key, val in KV_PATTERN.findall(line):
        if (val.startswith('"') and val.endswith('"')) or \
           (val.startswith("'") and val.endswith("'")):
            val = val[1:-1]
        result[key] = val
    return result


# ---------------------------------------------------------------------------
# Fallback canonical conversion
# ---------------------------------------------------------------------------

def fallback_to_canonical(line: str, line_num: int) -> Dict[str, Any]:
    canonical = {
        "line_number": line_num, "timestamp": None, "severity": None,
        "hostname": None, "process": None, "component": None, "pid": None, "message": line,
        "_format": "fallback", "metadata": {},
    }
    ts = extract_timestamp(line)
    if ts:
        canonical["timestamp"] = ts[0]
        canonical["metadata"]["timestamp_format"] = ts[1]
    kvs = extract_key_values(line)
    if len(kvs) >= 2:
        canonical["metadata"]["fields"] = kvs
        for kv_key, kv_val in kvs.items():
            target = _JSON_REVERSE_MAP.get(kv_key.lower())
            if target and canonical.get(target) is None:
                if target == "severity":
                    canonical["severity"] = normalize_severity(kv_val)
                else:
                    canonical[target] = kv_val
    return canonical


# ---------------------------------------------------------------------------
# File I/O (streaming, supports .gz / .bz2)
# ---------------------------------------------------------------------------

def open_log_file(filepath: str) -> Iterator[str]:
    if filepath.endswith(".gz"):
        f = gzip.open(filepath, "rt", errors="ignore")
    elif filepath.endswith(".bz2"):
        f = bz2.open(filepath, "rt", errors="ignore")
    else:
        f = open(filepath, "r", errors="ignore")
    try:
        yield from f
    finally:
        f.close()


# ---------------------------------------------------------------------------
# LLM Format Generator (optional — calls ollama-compatible API)
# ---------------------------------------------------------------------------

class LLMFormatGenerator:
    """
    Calls a local LLM to generate a regex pattern for unknown log formats.
    Falls back silently if the LLM endpoint is unreachable.
    """

    # Named groups the LLM should try to use
    EXPECTED_GROUPS = ["timestamp", "hostname", "process", "component", "pid", "level", "message"]

    PROMPT_TEMPLATE = (
        "Analyze these log lines and write a single Python regular expression "
        "to parse them.\n\n"
        "Rules:\n"
        "- Use named groups with these names where applicable: "
        "timestamp, hostname, process, component, pid, level, message\n"
        "- The regex must start with ^ and work with re.match()\n"
        "- Return ONLY the raw regex string on a single line\n"
        "- No explanation, no code fences, no backticks\n\n"
        "Sample lines:\n{lines}"
    )

    def __init__(self, endpoint: str = "http://localhost:11434",
                 model: str = "llama3", timeout: float = 10.0):
        self.endpoint = endpoint.rstrip("/")
        self.model = model
        self.timeout = timeout

    def try_generate_format(self, sample_lines: List[str]) -> Optional[LogFormat]:
        """
        Ask the LLM to generate a regex for the given sample lines.
        Returns a LogFormat if successful, None on any failure.
        """
        prompt = self.PROMPT_TEMPLATE.format(
            lines="\n".join(sample_lines[:10])
        )

        try:
            payload = json.dumps({
                "model": self.model,
                "prompt": prompt,
                "stream": False,
                "options": {"temperature": 0.1, "num_predict": 256},
            }).encode("utf-8")

            req = urllib.request.Request(
                f"{self.endpoint}/api/generate",
                data=payload,
                headers={"Content-Type": "application/json"},
            )

            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                body = json.loads(resp.read().decode("utf-8"))
                regex_str = body.get("response", "").strip()

            return self._validate_regex(regex_str, sample_lines)

        except (urllib.error.URLError, OSError, json.JSONDecodeError,
                KeyError, TimeoutError):
            # LLM not available — silent fallback
            return None

    def _validate_regex(self, regex_str: str, sample_lines: List[str]) -> Optional[LogFormat]:
        """Compile and test the LLM-generated regex against the sample."""
        if not regex_str or len(regex_str) < 10:
            return None

        # Strip code fences if the LLM ignored instructions
        regex_str = regex_str.strip("`").strip()
        if regex_str.startswith("python"):
            regex_str = regex_str[6:].strip()

        try:
            pattern = re.compile(regex_str)
        except re.error:
            return None

        # Verify it has at least one named group
        if not pattern.groupindex:
            return None

        # Test against sample — require >= 50% parse rate
        hits = sum(1 for line in sample_lines if pattern.match(line.strip()))
        if hits / max(len(sample_lines), 1) < 0.5:
            return None

        # Build field map from whatever groups the LLM used
        field_map = {}
        sev_field = None
        groups = set(pattern.groupindex.keys())
        for g in groups:
            if g == "level":
                sev_field = "level"
            elif g not in ("timestamp", "hostname", "process", "component", "message", "pid"):
                # Map unknown group names to canonical if possible
                target = _JSON_REVERSE_MAP.get(g.lower())
                if target:
                    field_map[g] = target

        fmt = LogFormat(
            name="llm_generated",
            pattern=pattern,
            fields=list(groups),
            priority=20,
            description=f"LLM-generated ({self.model})",
            field_map=field_map,
            severity_field=sev_field,
        )
        return fmt


# ---------------------------------------------------------------------------
# Core: UniversalLogParser
# ---------------------------------------------------------------------------

class UniversalLogParser:
    """
    Auto-detecting, self-healing, streaming log parser with canonical schema.

    For small files:
        parser = UniversalLogParser()
        records = parser.parse_file("access.log")

    For large files (10GB+):
        parser = UniversalLogParser()
        parser.parse_file_streaming("thunderbird.log", "output.ndjson")
    """

    def __init__(self, sample_size: int = 20, failure_threshold: int = 10,
                 llm_endpoint: Optional[str] = None, llm_model: str = "llama3"):
        self.sample_size = sample_size
        self.failure_threshold = failure_threshold
        self.detected_format: Optional[LogFormat] = None
        self.is_json_format: bool = False
        self.stats = self._empty_stats()

        # LLM bridge (None = disabled)
        self._llm: Optional[LLMFormatGenerator] = None
        if llm_endpoint:
            self._llm = LLMFormatGenerator(endpoint=llm_endpoint, model=llm_model)

    @staticmethod
    def _empty_stats() -> Dict[str, Any]:
        return {
            "total_lines": 0,
            "parsed_lines": 0,
            "failed_lines": 0,
            "multiline_continuations": 0,
            "format_redetections": 0,
            "replayed_lines": 0,
            "formats_used": [],
        }

    # ── Format detection ───────────────────────────────────────────────

    def detect_format(self, sample_lines: List[str]) -> Optional[LogFormat]:
        if not sample_lines:
            return None

        # JSON check first
        json_hits = sum(1 for l in sample_lines if try_parse_json_line(l) is not None)
        if json_hits / len(sample_lines) >= 0.7:
            self.is_json_format = True
            return None

        self.is_json_format = False

        # Score built-in formats
        scored = []
        for fmt in BUILTIN_FORMATS:
            s = fmt.score(sample_lines)
            if s > 0:
                scored.append((s, fmt.priority, fmt))

        if scored:
            scored.sort(key=lambda x: (x[0], x[1]), reverse=True)
            # Never let key_value win over a real format scoring >= 0.2
            non_kv = [(s, p, f) for s, p, f in scored if f.name != "key_value"]
            if non_kv and non_kv[0][0] >= 0.2:
                scored = non_kv

            if scored[0][0] >= 0.5:
                return scored[0][2]

        # No static format matched — try LLM if available
        if self._llm:
            print("[UniversalParser] No static format matched. Querying LLM...")
            llm_fmt = self._llm.try_generate_format(sample_lines)
            if llm_fmt:
                print(f"[UniversalParser] LLM generated regex with groups: "
                      f"{list(llm_fmt.pattern.groupindex.keys())}")
                return llm_fmt
            print("[UniversalParser] LLM did not return a usable pattern.")

        return None

    # ── Single-line parsing ────────────────────────────────────────────

    def _parse_line_raw(self, line: str, line_num: int) -> Optional[Dict[str, Any]]:
        """Parse with detected format. Returns canonical dict or None."""
        if not line:
            return None
        if self.is_json_format:
            parsed = try_parse_json_line(line)
            if parsed:
                return json_to_canonical(parsed, line_num)
        if self.detected_format:
            parsed = self.detected_format.try_parse(line)
            if parsed:
                return self.detected_format.to_canonical(parsed, line_num)
        return None

    # ── Core generator (shared by parse_file and parse_file_streaming) ─

    def _parse_iter(self, filepath: str) -> Generator[Dict[str, Any], None, None]:
        """
        Generator that yields canonical records one at a time.
        Never holds more than failure_threshold + 1 records in memory.
        """
        self.stats = self._empty_stats()

        # Phase 1: sample for format detection (consume only sample_size lines)
        file_iter = open_log_file(filepath)
        sample_lines: List[str] = []
        sample_raw: List[str] = []

        for raw_line in file_iter:
            stripped = raw_line.strip()
            if stripped:
                sample_lines.append(stripped)
                sample_raw.append(raw_line)
            else:
                sample_raw.append(raw_line)  # keep blanks for correct line count
            if len(sample_lines) >= self.sample_size:
                break

        if not sample_lines:
            print(f"[UniversalParser] File is empty: {filepath}")
            return

        self.detected_format = self.detect_format(sample_lines)
        if self.is_json_format:
            fmt_label = "JSON lines"
        elif self.detected_format:
            fmt_label = f"{self.detected_format.name} ({self.detected_format.description})"
        else:
            fmt_label = "fallback (heuristic extraction)"
        self.stats["formats_used"].append(fmt_label)
        print(f"[UniversalParser] Auto-detected format: {fmt_label}")

        # Phase 2: stream through all lines
        # Replay sample_raw first (they were consumed from file_iter),
        # then continue with the rest of file_iter.
        line_num = 0
        failure_buffer: List[Tuple[str, int]] = []
        consecutive_failures = 0
        last_record: Optional[Dict[str, Any]] = None
        last_yielded = False

        def flush_buffer_as_fallback():
            """Yield failure-buffered lines as fallback records."""
            nonlocal failure_buffer
            for buf_line, buf_num in failure_buffer:
                fb = fallback_to_canonical(buf_line, buf_num)
                self.stats["failed_lines"] += 1
                self.stats["parsed_lines"] += 1
                yield fb
            failure_buffer = []

        def replay_buffer_with_new_format():
            """Re-parse failure buffer under the newly detected format."""
            nonlocal failure_buffer
            for buf_line, buf_num in failure_buffer:
                reparsed = self._parse_line_raw(buf_line, buf_num)
                if reparsed:
                    self.stats["replayed_lines"] += 1
                    self.stats["parsed_lines"] += 1
                    yield reparsed
                else:
                    fb = fallback_to_canonical(buf_line, buf_num)
                    self.stats["replayed_lines"] += 1
                    self.stats["failed_lines"] += 1
                    self.stats["parsed_lines"] += 1
                    yield fb
            failure_buffer = []

        # Use a flag to chain sample_raw with file_iter without enumerate
        import itertools
        full_iter = itertools.chain(sample_raw, file_iter)

        for raw_line in full_iter:
            line_num += 1
            self.stats["total_lines"] += 1
            stripped = raw_line.strip()
            if not stripped:
                continue

            # Multi-line continuation: only when NOT in a drift zone,
            # the previous record was from a real format, AND the line
            # structurally looks like a continuation (indented, stack frame, etc.)
            if (consecutive_failures == 0
                    and last_record is not None
                    and last_record["_format"] != "fallback"
                    and is_continuation_line(raw_line)):
                last_record["message"] += "\n" + stripped
                self.stats["multiline_continuations"] += 1
                continue

            # Normal parse attempt
            parsed = self._parse_line_raw(stripped, line_num)

            if parsed:
                # Flush any pending failures as fallback before this success
                if failure_buffer:
                    yield from flush_buffer_as_fallback()
                    consecutive_failures = 0

                yield parsed
                self.stats["parsed_lines"] += 1
                last_record = parsed
                consecutive_failures = 0
            else:
                consecutive_failures += 1
                failure_buffer.append((stripped, line_num))

                if consecutive_failures >= self.failure_threshold:
                    # Self-healing: use failure buffer as re-detection sample
                    print(f"[UniversalParser] Format drift at line {line_num}. "
                          f"Re-detecting from {len(failure_buffer)} buffered lines...")
                    self.stats["format_redetections"] += 1

                    new_sample = [s for s, _ in failure_buffer]
                    new_format = self.detect_format(new_sample)

                    if self.is_json_format:
                        new_label = "JSON lines"
                    elif new_format:
                        new_label = new_format.name
                        self.detected_format = new_format
                    else:
                        new_label = "fallback"
                    self.stats["formats_used"].append(new_label)
                    print(f"[UniversalParser] Switched to format: {new_label}")

                    # Replay all buffered lines under new format
                    yield from replay_buffer_with_new_format()
                    consecutive_failures = 0
                    failure_buffer = []

        # End of file: flush remaining failures as fallback
        if failure_buffer:
            yield from flush_buffer_as_fallback()

    # ── Public API ─────────────────────────────────────────────────────

    def parse_file(self, filepath: str) -> List[Dict[str, Any]]:
        """
        Parse to list. Suitable for files that fit in RAM.
        For large files (>1GB), use parse_file_streaming() instead.
        """
        if not os.path.isfile(filepath):
            raise FileNotFoundError(f"Log file not found: {filepath}")
        return list(self._parse_iter(filepath))

    def parse_file_streaming(self, filepath: str, output_path: str,
                             include_metadata: bool = True):
        """
        Stream-parse directly to NDJSON file. Never holds all records in RAM.
        Suitable for 10GB+ log files.
        """
        if not os.path.isfile(filepath):
            raise FileNotFoundError(f"Log file not found: {filepath}")

        os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
        record_count = 0

        with open(output_path, "w", encoding="utf-8") as out:
            for record in self._parse_iter(filepath):
                out.write(json.dumps(record, ensure_ascii=False) + "\n")
                record_count += 1

            # Write metadata as the last line (so streaming consumers can
            # ignore it or read it after exhausting the stream)
            if include_metadata:
                meta_line = json.dumps({"_metadata": self._build_metadata()},
                                       ensure_ascii=False)
                out.write(meta_line + "\n")

        print(f"[UniversalParser] Streamed {record_count} records to {output_path}")

    def save_json(self, records: List[Dict[str, Any]], output_path: str,
                  fmt: str = "ndjson", include_metadata: bool = True):
        """Save an already-collected record list to file."""
        os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)

        if fmt == "ndjson":
            with open(output_path, "w", encoding="utf-8") as f:
                if include_metadata:
                    f.write(json.dumps({"_metadata": self._build_metadata()},
                                       ensure_ascii=False) + "\n")
                for record in records:
                    f.write(json.dumps(record, ensure_ascii=False) + "\n")
        else:
            payload = {
                "metadata": self._build_metadata(),
                "logs": records,
            } if include_metadata else records
            with open(output_path, "w", encoding="utf-8") as f:
                json.dump(payload, f, indent=2, ensure_ascii=False)

        print(f"[UniversalParser] Saved {len(records)} records to {output_path} ({fmt})")

    def _build_metadata(self) -> Dict[str, Any]:
        s = self.stats
        total = max(s["total_lines"], 1)
        return {
            "parser": "UniversalDynamicLogParser",
            "version": "3.0",
            "total_lines": s["total_lines"],
            "parsed_lines": s["parsed_lines"],
            "failed_lines": s["failed_lines"],
            "multiline_continuations": s["multiline_continuations"],
            "format_redetections": s["format_redetections"],
            "replayed_lines": s["replayed_lines"],
            "formats_detected": s["formats_used"],
            "parse_rate": f"{s['parsed_lines'] / total * 100:.1f}%",
        }

    def print_summary(self):
        s = self.stats
        total = max(s["total_lines"], 1)
        print(f"\n{'=' * 60}")
        print(f"  UNIVERSAL LOG PARSER v3.0 - SUMMARY")
        print(f"{'=' * 60}")
        print(f"  Total lines read:       {s['total_lines']:,}")
        print(f"  Successfully parsed:    {s['parsed_lines']:,}")
        print(f"  Fallback (failed fmt):  {s['failed_lines']:,}")
        print(f"  Multi-line joins:       {s['multiline_continuations']:,}")
        print(f"  Format re-detections:   {s['format_redetections']}")
        print(f"  Replayed after drift:   {s['replayed_lines']:,}")
        print(f"  Formats used:           {', '.join(s['formats_used'])}")
        print(f"  Parse success rate:     {s['parsed_lines'] / total * 100:.1f}%")
        print(f"{'=' * 60}\n")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(
        description="Universal Dynamic Log Parser v3.0"
    )
    ap.add_argument("input", help="Path to log file (.log, .txt, .gz, .bz2)")
    ap.add_argument("-o", "--output", default=None,
                    help="Output path (default: <input>.parsed.ndjson)")
    ap.add_argument("--format", choices=["ndjson", "pretty"], default="ndjson",
                    help="Output format (default: ndjson)")
    ap.add_argument("--sample-size", type=int, default=20,
                    help="Lines to sample for detection (default: 20)")
    ap.add_argument("--failure-threshold", type=int, default=10,
                    help="Consecutive failures before re-detect (default: 10)")
    ap.add_argument("--no-metadata", action="store_true")
    ap.add_argument("--llm-endpoint", default=None,
                    help="Ollama-compatible API URL (e.g. http://localhost:11434)")
    ap.add_argument("--llm-model", default="llama3",
                    help="LLM model name (default: llama3)")
    ap.add_argument("--streaming", action="store_true",
                    help="Use streaming mode for large files (writes NDJSON directly)")
    args = ap.parse_args()

    if not args.output:
        base, _ = os.path.splitext(args.input)
        ext = ".ndjson" if args.format == "ndjson" else ".json"
        args.output = base + ".parsed" + ext

    parser = UniversalLogParser(
        sample_size=args.sample_size,
        failure_threshold=args.failure_threshold,
        llm_endpoint=args.llm_endpoint,
        llm_model=args.llm_model,
    )

    if args.streaming:
        parser.parse_file_streaming(args.input, args.output,
                                    include_metadata=not args.no_metadata)
    else:
        records = parser.parse_file(args.input)
        parser.save_json(records, args.output, fmt=args.format,
                         include_metadata=not args.no_metadata)

    parser.print_summary()


if __name__ == "__main__":
    main()
