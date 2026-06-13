"""
Structured Log Parser — Parses LogPAI Linux syslog format into structured records.

Handles all process/component/PID formats found in the Linux_2k.log dataset:
  - sshd(pam_unix)[19939]  → process=sshd, component=pam_unix, pid=19939
  - su(pam_unix)[21416]    → process=su,   component=pam_unix, pid=21416
  - logrotate              → process=logrotate, component=None, pid=None
  - ftpd[29504]            → process=ftpd,  component=None,  pid=29504
  - syslogd 1.4.1          → process=syslogd, component=None, pid=None
  - snmpd[2318]            → process=snmpd, component=None,  pid=2318
  - cups                   → process=cups,  component=None,  pid=None

Each parsed record contains: timestamp, hostname, process, component, pid,
message, event (normalized), metadata (extracted key-value pairs), raw_log,
and line_number.
"""

import re
import json
from typing import Optional


# ─── Primary Regex ──────────────────────────────────────────────────────────────
# Matches the full BSD-style syslog line format used by LogPAI Linux logs.
#
# Groups:
#   timestamp  – e.g. "Jun 14 15:16:01"
#   hostname   – e.g. "combo"
#   process    – e.g. "sshd", "su", "logrotate", "syslogd"
#   component  – optional, e.g. "pam_unix" from "sshd(pam_unix)"
#   pid        – optional, e.g. "19939" from "[19939]"
#   (version)  – optional non-capturing, e.g. "1.4.1" after "syslogd"
#   message    – everything after the ": " delimiter

SYSLOG_PATTERN_BSD = re.compile(
    r'^(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+'
    r'(?P<hostname>\S+)\s+'
    r'(?P<process>[\w.-]+)'
    r'(?:\((?P<component>[^)]+)\))?'
    r'(?:\[(?P<pid>\d+)\])?'
    r'(?:\s+[\d.]+)?'          # optional version like "1.4.1"
    r'\s*:\s*'
    r'(?P<message>.+)$'
)

# Matches ISO8601 syslog format (used by auth.log)
# e.g. 2026-04-05T15:35:01.469007+05:30 pi CRON[1461]: message
SYSLOG_PATTERN_ISO = re.compile(
    r'^(?P<timestamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?[+-]\d{2}:\d{2})\s+'
    r'(?P<hostname>\S+)\s+'
    r'(?P<process>[\w.()-]+)'
    r'(?:\((?P<component>[^)]+)\))?'
    r'(?:\[(?P<pid>\d+)\])?'
    r'\s*:\s*'
    r'(?P<message>.+)$'
)


# ─── Event Classification Rules ────────────────────────────────────────────────
# Ordered list of (substring/keyword, normalized_event_name) pairs.
# First match wins — more specific patterns come first.

EVENT_RULES = [
    ('authentication failure',   'authentication_failure'),
    ('Failed password',          'authentication_failure'),
    ('check pass',               'check_pass'),
    ('session opened',           'session_opened'),
    ('session closed',           'session_closed'),
    ('ALERT exited abnormally',  'abnormal_exit'),
    ('connection from',          'connection'),
    ('startup succeeded',        'service_started'),
    ('shutdown succeeded',       'service_stopped'),
    ('restart',                  'service_restart'),
    ('Received SNMP',            'snmp_received'),
    ('timed out',                'timeout'),
    ('Accepted',                 'authentication_success'),
    ('user NOT in sudoers',      'sudo_denied'),
    ('COMMAND=',                 'sudo_command'),
]


# ─── Metadata Extraction Patterns ──────────────────────────────────────────────

# key=value pairs for known syslog metadata fields
KV_PATTERN = re.compile(
    r'\b(?P<key>logname|uid|euid|tty|ruser|rhost|user|session|exit_code)'
    r'=(?P<value>\S*)'
)

# "for user <username>" pattern (e.g. "session opened for user cyrus")
FOR_USER_PATTERN = re.compile(r'for user\s+(\S+)')

# "by (uid=N)" pattern (e.g. "by (uid=0)")
BY_UID_PATTERN = re.compile(r'by\s+\(uid=(\d+)\)')

# "connection from IP (hostname)" pattern used in ftpd logs
CONNECTION_PATTERN = re.compile(
    r'connection from\s+(\d+\.\d+\.\d+\.\d+)\s+\(([^)]*)\)'
)

# Standalone IP addresses (for "from IP" patterns not covered by connection)
FROM_IP_PATTERN = re.compile(r'from\s+(\d+\.\d+\.\d+\.\d+)')


# ─── Helper Functions ──────────────────────────────────────────────────────────

def _classify_event(message: str) -> str:
    """
    Derive a normalized event name from the message content.

    Scans the message for known keywords/substrings and returns the
    corresponding normalized event type. Returns 'unknown' if no rule matches.

    Args:
        message: The log message text.

    Returns:
        Normalized event string (e.g. 'authentication_failure', 'session_opened').
    """
    for keyword, event_name in EVENT_RULES:
        if keyword in message:
            return event_name
    return 'unknown'


def _extract_metadata(message: str) -> dict:
    """
    Extract structured metadata key-value pairs from the message.

    Handles:
      - Explicit key=value pairs (logname, uid, euid, tty, ruser, rhost, user, etc.)
      - "for user X" → user=X
      - "by (uid=N)" → uid=N (as integer)
      - "connection from IP (hostname)" → source_ip, source_host
      - "from IP" → source_ip
      - Numeric coercion for uid/euid fields

    Args:
        message: The log message text.

    Returns:
        Dictionary of extracted metadata. Empty dict if nothing extracted.
    """
    metadata = {}

    # Extract explicit key=value pairs
    for match in KV_PATTERN.finditer(message):
        key = match.group('key')
        value = match.group('value')
        # Coerce uid/euid to integers when possible
        if key in ('uid', 'euid') and value.isdigit():
            metadata[key] = int(value)
        else:
            metadata[key] = value

    # Extract "for user X" — only add if 'user' not already captured as key=value
    for_user_match = FOR_USER_PATTERN.search(message)
    if for_user_match:
        user_val = for_user_match.group(1)
        # Prefer the "for user" extraction; it is more semantically meaningful
        metadata['user'] = user_val

    # Extract "by (uid=N)" — override uid if present
    by_uid_match = BY_UID_PATTERN.search(message)
    if by_uid_match:
        metadata['uid'] = int(by_uid_match.group(1))

    # Extract connection from IP (hostname) — ftpd pattern
    conn_match = CONNECTION_PATTERN.search(message)
    if conn_match:
        metadata['source_ip'] = conn_match.group(1)
        hostname = conn_match.group(2).strip()
        if hostname:
            metadata['source_host'] = hostname
    else:
        # Fallback: extract "from IP" for SNMP and similar patterns
        from_ip_match = FROM_IP_PATTERN.search(message)
        if from_ip_match:
            metadata['source_ip'] = from_ip_match.group(1)

    return metadata


# ─── Public API ─────────────────────────────────────────────────────────────────

def parse_line(line: str, line_number: int = 0) -> Optional[dict]:
    """
    Parse a single syslog line into a structured record dictionary.

    Args:
        line: Raw syslog line string (may include trailing whitespace/newline).
        line_number: Optional line number for tracking position in the file.

    Returns:
        Dictionary with keys: timestamp, hostname, process, component, pid,
        message, event, metadata, raw_log, line_number.
        Returns None if the line cannot be parsed.
    """
    line = line.strip()
    if not line or len(line) < 10:
        return None

    match = SYSLOG_PATTERN_BSD.match(line)
    if not match:
        match = SYSLOG_PATTERN_ISO.match(line)
        if not match:
            return None

    groups = match.groupdict()
    message = groups['message'].strip()

    # Convert PID to integer if present
    pid = int(groups['pid']) if groups['pid'] else None

    return {
        'timestamp':   groups['timestamp'],
        'hostname':    groups['hostname'],
        'process':     groups['process'],
        'component':   groups.get('component'),    # None if absent
        'pid':         pid,
        'message':     message,
        'event':       _classify_event(message),
        'metadata':    _extract_metadata(message),
        'raw_log':     line,
        'line_number': line_number,
    }


def parse_file(filepath: str) -> list[dict]:
    """
    Parse all lines in a log file into structured records.

    Skips blank lines and unparseable entries (logged to stderr count).

    Args:
        filepath: Path to the log file.

    Returns:
        List of successfully parsed record dictionaries.
    """
    records = []
    failed = 0

    with open(filepath, 'r', errors='ignore') as f:
        for line_num, line in enumerate(f, start=1):
            record = parse_line(line, line_number=line_num)
            if record:
                records.append(record)
            else:
                failed += 1

    total = len(records) + failed
    accuracy = (len(records) / total * 100) if total > 0 else 0.0
    print(f"[StructuredParser] Parsed {len(records):,} / {total:,} lines "
          f"({accuracy:.1f}% accuracy, {failed} failed)")
    return records


def parse_file_to_json(filepath: str, output_path: str) -> None:
    """
    Parse a log file and save all records as a JSON array.

    Args:
        filepath: Path to the input log file.
        output_path: Path where the JSON output will be written.
    """
    records = parse_file(filepath)
    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(records, f, indent=2, ensure_ascii=False)
    print(f"[StructuredParser] Saved {len(records):,} records to {output_path}")


def parse_file_to_ndjson(filepath: str, output_path: str) -> None:
    """
    Parse a log file and save records as NDJSON (one JSON object per line).

    Args:
        filepath: Path to the input log file.
        output_path: Path where the NDJSON output will be written.
    """
    records = parse_file(filepath)
    with open(output_path, 'w', encoding='utf-8') as f:
        for record in records:
            f.write(json.dumps(record, ensure_ascii=False) + '\n')
    print(f"[StructuredParser] Saved {len(records):,} records (NDJSON) to {output_path}")


def get_parse_stats(records: list[dict]) -> dict:
    """
    Compute parsing statistics across a list of parsed records.

    Args:
        records: List of parsed record dictionaries from parse_line/parse_file.

    Returns:
        Dictionary with keys: total_lines, parsed_lines, failed_lines,
        accuracy_pct, processes_found, events_found, unique_hosts.
    """
    parsed = len(records)
    # Count unique values across key fields
    processes = set()
    events = set()
    hosts = set()

    for r in records:
        processes.add(r.get('process'))
        events.add(r.get('event'))
        hosts.add(r.get('hostname'))

    return {
        'total_lines':     parsed,       # from parsed records only
        'parsed_lines':    parsed,
        'failed_lines':    0,            # not tracked at record level
        'accuracy_pct':    100.0 if parsed > 0 else 0.0,
        'processes_found': sorted(processes),
        'events_found':    sorted(events),
        'unique_hosts':    sorted(hosts),
    }


# ─── Main — Quick Self-Test ────────────────────────────────────────────────────

if __name__ == '__main__':
    # 10 representative sample lines from the LogPAI Linux_2k.log dataset
    SAMPLE_LINES = [
        "Jun 14 15:16:01 combo sshd(pam_unix)[19939]: authentication failure; logname= uid=0 euid=0 tty=NODEVssh ruser= rhost=218.188.2.4",
        "Jun 15 02:04:59 combo sshd(pam_unix)[20882]: authentication failure; logname= uid=0 euid=0 tty=NODEVssh ruser= rhost=220-135-151-1.hinet-ip.hinet.net  user=root",
        "Jun 15 04:06:18 combo su(pam_unix)[21416]: session opened for user cyrus by (uid=0)",
        "Jun 15 04:06:19 combo su(pam_unix)[21416]: session closed for user cyrus",
        "Jun 15 04:06:20 combo logrotate: ALERT exited abnormally with [1]",
        "Jun 17 07:07:00 combo ftpd[29504]: connection from 24.54.76.216 (24-54-76-216.bflony.adelphia.net) at Fri Jun 17 07:07:00 2005",
        "Jun 19 04:08:57 combo cups: cupsd shutdown succeeded",
        "Jun 19 04:09:02 combo cups: cupsd startup succeeded",
        "Jun 19 04:09:11 combo syslogd 1.4.1: restart.",
        "Jun 20 04:44:39 combo snmpd[2318]: Received SNMP packet(s) from 67.170.148.126",
    ]

    print("=" * 80)
    print("Structured Log Parser — Self-Test")
    print("=" * 80)

    for i, line in enumerate(SAMPLE_LINES, start=1):
        record = parse_line(line, line_number=i)
        if record:
            print(f"\n--- Line {i} ---")
            print(f"  Timestamp : {record['timestamp']}")
            print(f"  Hostname  : {record['hostname']}")
            print(f"  Process   : {record['process']}")
            print(f"  Component : {record['component']}")
            print(f"  PID       : {record['pid']}")
            print(f"  Event     : {record['event']}")
            print(f"  Message   : {record['message'][:80]}...")
            if record['metadata']:
                print(f"  Metadata  : {record['metadata']}")
        else:
            print(f"\n--- Line {i} --- FAILED TO PARSE")
            print(f"  Raw: {line[:80]}")

    print("\n" + "=" * 80)
    print("Summary Statistics:")
    records = [parse_line(l, i) for i, l in enumerate(SAMPLE_LINES, 1)]
    records = [r for r in records if r]
    stats = get_parse_stats(records)
    for k, v in stats.items():
        print(f"  {k:20s}: {v}")
    print("=" * 80)
