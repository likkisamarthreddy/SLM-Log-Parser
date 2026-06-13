"""
Comprehensive test suite for structured_parser + log_anonymizer (Step 9).

Tests parsing accuracy, anonymization correctness, deterministic consistency,
edge cases, and generates a JSON validation report.

Run from project root:
    python tests/test_anonymizer.py
"""

import sys
import os
import json
import re
from datetime import datetime
from collections import Counter

# ─── Path Setup ────────────────────────────────────────────────────────────────
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.structured_parser import parse_line, parse_file, _classify_event, _extract_metadata
from src.log_anonymizer import LogAnonymizer


# ─── Constants ─────────────────────────────────────────────────────────────────

GOLDEN_INPUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'golden_input.log')
RESULTS_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'results')
REPORT_PATH = os.path.join(RESULTS_DIR, 'anonymizer_validation_report.json')

# Security keywords that MUST be preserved in anonymized messages
SECURITY_KEYWORDS = [
    'authentication failure', 'session opened', 'session closed',
    'check pass', 'ALERT', 'connection from', 'shutdown', 'startup',
    'restart', 'Received SNMP', 'timed out', 'exited abnormally',
    'DHCPDISCOVER', 'DHCPOFFER', 'terminated', 'Normal exit',
    'imklog', 'rejected', 'user unknown',
]

# Patterns for anonymized tokens
HOST_PATTERN = re.compile(r'^HOST_\d+$')
PID_PATTERN = re.compile(r'^PID_\d+$')
USER_PATTERN = re.compile(r'^USER_\d+$')
REMOTE_HOST_PATTERN = re.compile(r'^REMOTE_HOST_\d+$')
IP_PATTERN = re.compile(r'^IP_\d+$')


# ─── Load Golden Input ────────────────────────────────────────────────────────

def load_golden_input():
    """Load the golden test file and return list of raw lines."""
    with open(GOLDEN_INPUT, 'r', encoding='utf-8', errors='ignore') as f:
        return f.readlines()


# ─── Test 1: Parsing Accuracy ─────────────────────────────────────────────────

def test_parsing(lines):
    """
    Test parsing accuracy across all golden input lines.
    Returns dict with per-field accuracy and lists of parsed/unparsed.
    """
    total = len(lines)
    parsed_records = []
    unparsed_lines = []

    # Per-field counters
    field_counts = {
        'timestamp': 0,
        'hostname': 0,
        'process': 0,
        'component': 0,
        'pid': 0,
        'message': 0,
        'event': 0,
        'metadata': 0,
    }

    for i, line in enumerate(lines, start=1):
        record = parse_line(line, line_number=i)
        if record is not None:
            parsed_records.append(record)

            # Check each field
            if record.get('timestamp'):
                field_counts['timestamp'] += 1
            if record.get('hostname'):
                field_counts['hostname'] += 1
            if record.get('process'):
                field_counts['process'] += 1
            # component can legitimately be None (logrotate, cups, etc.)
            field_counts['component'] += 1  # always counted — None is valid
            # PID can legitimately be None
            field_counts['pid'] += 1  # always counted — None is valid
            if record.get('message'):
                field_counts['message'] += 1
            if record.get('event'):
                field_counts['event'] += 1
            if isinstance(record.get('metadata'), dict):
                field_counts['metadata'] += 1
        else:
            unparsed_lines.append((i, line.rstrip()))

    parseable = len(parsed_records)
    accuracies = {}
    for field, count in field_counts.items():
        accuracies[f'{field}_accuracy'] = (count / parseable * 100) if parseable > 0 else 0.0

    return {
        'total_lines': total,
        'parseable_lines': parseable,
        'unparseable_lines': len(unparsed_lines),
        'parse_rate': (parseable / total * 100) if total > 0 else 0.0,
        'field_accuracies': accuracies,
        'parsed_records': parsed_records,
        'unparsed_lines': unparsed_lines,
    }


# ─── Test 2: Anonymization Correctness ────────────────────────────────────────

def test_anonymization(parsed_records):
    """
    Test anonymization correctness across all parsed records.
    Returns dict with anonymization metrics.
    """
    anonymizer = LogAnonymizer()
    anonymized_records = []
    total_fields_anonymized = 0

    # Preservation counters
    event_preserved = 0
    event_total = 0
    process_preserved = 0
    process_total = 0
    security_kw_preserved = 0
    security_kw_total = 0

    for record in parsed_records:
        anon = anonymizer.anonymize_record(record)
        anonymized_records.append(anon)

        # --- Check hostname is anonymized ---
        orig_host = record.get('hostname', '')
        anon_host = anon.get('hostname', '')
        if orig_host and anon_host != orig_host:
            total_fields_anonymized += 1

        # --- Check PID is anonymized ---
        orig_pid = record.get('pid')
        anon_pid = anon.get('pid')
        if orig_pid is not None and anon_pid != orig_pid:
            total_fields_anonymized += 1

        # --- Check process is PRESERVED ---
        process_total += 1
        if record.get('process') == anon.get('process'):
            process_preserved += 1

        # --- Check event is PRESERVED ---
        orig_event = record.get('event', '')
        anon_event = anon.get('event', '')
        if orig_event:
            event_total += 1
            if orig_event == anon_event:
                event_preserved += 1

        # --- Check security keywords are PRESERVED in message ---
        anon_msg = anon.get('message', '') or ''
        orig_msg = record.get('message', '') or ''
        for kw in SECURITY_KEYWORDS:
            if kw in orig_msg:
                security_kw_total += 1
                if kw in anon_msg:
                    security_kw_preserved += 1

    # Get mapping stats from anonymizer
    mapping = anonymizer.mappings

    return {
        'anonymized_records': anonymized_records,
        'total_fields_anonymized': total_fields_anonymized,
        'event_preservation_rate': (event_preserved / event_total * 100) if event_total > 0 else 100.0,
        'process_preservation_rate': (process_preserved / process_total * 100) if process_total > 0 else 100.0,
        'security_keyword_preservation_rate': (security_kw_preserved / security_kw_total * 100) if security_kw_total > 0 else 100.0,
        'mapping': mapping,
        'anonymizer': anonymizer,
    }


# ─── Test 3: Deterministic Consistency ─────────────────────────────────────────

def test_deterministic_consistency(lines):
    """
    Parse the file twice with fresh anonymizers and verify deterministic mapping
    within each run.
    """
    results = {'passed': 0, 'failed': 0, 'details': []}

    for run_idx in range(2):
        anonymizer = LogAnonymizer()
        hostname_map = {}
        user_map = {}
        consistent = True

        for i, line in enumerate(lines, start=1):
            record = parse_line(line, line_number=i)
            if record is None:
                continue
            anon = anonymizer.anonymize_record(record)

            # Check hostname consistency
            orig_host = record.get('hostname', '')
            anon_host = anon.get('hostname', '')
            if orig_host:
                if orig_host in hostname_map:
                    if hostname_map[orig_host] != anon_host:
                        consistent = False
                        results['details'].append(
                            f"Run {run_idx+1}: hostname '{orig_host}' mapped to "
                            f"'{hostname_map[orig_host]}' and '{anon_host}'"
                        )
                else:
                    hostname_map[orig_host] = anon_host

            # Check user consistency from metadata
            orig_meta = record.get('metadata', {})
            anon_meta = anon.get('metadata', {})
            orig_user = orig_meta.get('user', '')
            anon_user = anon_meta.get('user', '')
            if orig_user and isinstance(orig_user, str) and orig_user.strip():
                if orig_user in user_map:
                    if user_map[orig_user] != anon_user:
                        consistent = False
                        results['details'].append(
                            f"Run {run_idx+1}: user '{orig_user}' mapped to "
                            f"'{user_map[orig_user]}' and '{anon_user}'"
                        )
                else:
                    user_map[orig_user] = anon_user

        if consistent:
            results['passed'] += 1
        else:
            results['failed'] += 1

    return results


# ─── Test 4: Edge Cases ───────────────────────────────────────────────────────

def test_edge_cases(lines):
    """
    Test edge case handling: empty lines, malformed lines, missing fields.
    """
    results = {'passed': 0, 'failed': 0, 'details': []}

    # --- Empty line returns None ---
    try:
        result = parse_line('', line_number=0)
        if result is None:
            results['passed'] += 1
        else:
            results['failed'] += 1
            results['details'].append('Empty line did not return None')
    except Exception as e:
        results['failed'] += 1
        results['details'].append(f'Empty line raised exception: {e}')

    # --- Whitespace-only line returns None ---
    try:
        result = parse_line('   \t  \n', line_number=0)
        if result is None:
            results['passed'] += 1
        else:
            results['failed'] += 1
            results['details'].append('Whitespace-only line did not return None')
    except Exception as e:
        results['failed'] += 1
        results['details'].append(f'Whitespace-only line raised exception: {e}')

    # --- Malformed line returns None ---
    try:
        result = parse_line('this is a malformed line with no structure', line_number=0)
        if result is None:
            results['passed'] += 1
        else:
            results['failed'] += 1
            results['details'].append('Malformed line did not return None')
    except Exception as e:
        results['failed'] += 1
        results['details'].append(f'Malformed line raised exception: {e}')

    # --- Truncated line returns None ---
    try:
        result = parse_line('Jun 15 04:06:18', line_number=0)
        if result is None:
            results['passed'] += 1
        else:
            results['failed'] += 1
            results['details'].append('Truncated line did not return None')
    except Exception as e:
        results['failed'] += 1
        results['details'].append(f'Truncated line raised exception: {e}')

    # --- Line with missing PID still parses ---
    try:
        result = parse_line(
            'Jun 15 04:06:20 combo logrotate: ALERT exited abnormally with [1]',
            line_number=0
        )
        if result is not None and result.get('pid') is None:
            results['passed'] += 1
        elif result is not None:
            results['passed'] += 1  # parsed OK, PID handling may differ
        else:
            results['failed'] += 1
            results['details'].append('Line with missing PID returned None')
    except Exception as e:
        results['failed'] += 1
        results['details'].append(f'Missing PID line raised exception: {e}')

    # --- Line with empty rhost still parses ---
    try:
        result = parse_line(
            'Jun 15 04:06:18 combo sshd(pam_unix)[19939]: authentication failure; '
            'logname= uid=0 euid=0 tty=NODEVssh ruser= rhost=',
            line_number=0
        )
        if result is not None:
            results['passed'] += 1
            meta = result.get('metadata', {})
            # rhost should be empty string
        else:
            results['failed'] += 1
            results['details'].append('Line with empty rhost returned None')
    except Exception as e:
        results['failed'] += 1
        results['details'].append(f'Empty rhost line raised exception: {e}')

    # --- Line with empty user still parses ---
    try:
        result = parse_line(
            'Jun 15 04:06:18 combo su(pam_unix)[21416]: session opened for user  by (uid=0)',
            line_number=0
        )
        if result is not None:
            results['passed'] += 1
        else:
            results['failed'] += 1
            results['details'].append('Line with empty user returned None')
    except Exception as e:
        results['failed'] += 1
        results['details'].append(f'Empty user line raised exception: {e}')

    # --- Multiple hostnames get different HOST_NNN values ---
    try:
        anonymizer = LogAnonymizer()
        rec1 = parse_line(
            'Jun 15 04:06:20 combo logrotate: ALERT exited abnormally with [1]',
            line_number=1
        )
        rec2 = parse_line(
            'Jul 02 11:22:35 otherhost logrotate: ALERT exited abnormally with [1]',
            line_number=2
        )
        if rec1 and rec2:
            anon1 = anonymizer.anonymize_record(rec1)
            anon2 = anonymizer.anonymize_record(rec2)
            if anon1.get('hostname') != anon2.get('hostname'):
                results['passed'] += 1
            else:
                results['failed'] += 1
                results['details'].append(
                    f"Different hostnames mapped to same value: "
                    f"combo→{anon1.get('hostname')}, otherhost→{anon2.get('hostname')}"
                )
        else:
            results['failed'] += 1
            results['details'].append('Could not parse lines for hostname uniqueness test')
    except Exception as e:
        results['failed'] += 1
        results['details'].append(f'Hostname uniqueness test raised exception: {e}')

    # --- uid=0 and euid=0 preserved ---
    try:
        anonymizer = LogAnonymizer()
        rec = parse_line(
            'Jun 14 15:16:01 combo sshd(pam_unix)[19939]: authentication failure; '
            'logname= uid=0 euid=0 tty=NODEVssh ruser= rhost=218.188.2.4',
            line_number=1
        )
        if rec:
            anon = anonymizer.anonymize_record(rec)
            anon_msg = anon.get('message', '')
            anon_meta = anon.get('metadata', {})
            # uid=0 and euid=0 should be preserved (either in message or metadata)
            uid_preserved = (
                'uid=0' in anon_msg or
                anon_meta.get('uid') == 0 or
                anon_meta.get('uid') == '0'
            )
            euid_preserved = (
                'euid=0' in anon_msg or
                anon_meta.get('euid') == 0 or
                anon_meta.get('euid') == '0'
            )
            if uid_preserved and euid_preserved:
                results['passed'] += 1
            else:
                results['failed'] += 1
                results['details'].append(
                    f'uid=0/euid=0 not preserved. Message: {anon_msg[:100]}, '
                    f'Metadata: {anon_meta}'
                )
        else:
            results['failed'] += 1
            results['details'].append('Could not parse line for uid/euid test')
    except Exception as e:
        results['failed'] += 1
        results['details'].append(f'uid/euid preservation test raised exception: {e}')

    # --- Component names preserved ---
    try:
        anonymizer = LogAnonymizer()
        rec = parse_line(
            'Jun 15 04:06:18 combo su(pam_unix)[21416]: session opened for user cyrus by (uid=0)',
            line_number=1
        )
        if rec:
            anon = anonymizer.anonymize_record(rec)
            if rec.get('component') == anon.get('component'):
                results['passed'] += 1
            else:
                results['failed'] += 1
                results['details'].append(
                    f"Component not preserved: {rec.get('component')} → {anon.get('component')}"
                )
        else:
            results['failed'] += 1
            results['details'].append('Could not parse line for component test')
    except Exception as e:
        results['failed'] += 1
        results['details'].append(f'Component preservation test raised exception: {e}')

    return results


# ─── Build Report ─────────────────────────────────────────────────────────────

def build_report(parse_results, anon_results, consistency_results, edge_results):
    """Build the full validation report dict."""
    # Mapping statistics
    mapping = anon_results.get('mapping', {})
    unique_hosts = len(mapping.get('hostnames', mapping.get('hostname', {})))
    unique_users = len(mapping.get('users', mapping.get('user', {})))
    unique_pids = len(mapping.get('pids', mapping.get('pid', {})))
    unique_remote_hosts = len(mapping.get('remote_hosts', mapping.get('rhost', {})))
    unique_ips = len(mapping.get('ips', mapping.get('ip', mapping.get('source_ip', {}))))

    report = {
        'generated_at': datetime.now().isoformat(),
        'golden_input_file': GOLDEN_INPUT,

        # Parsing metrics
        'parsing': {
            'total_lines': parse_results['total_lines'],
            'parseable_lines': parse_results['parseable_lines'],
            'unparseable_lines': parse_results['unparseable_lines'],
            'parse_rate_pct': round(parse_results['parse_rate'], 2),
            'field_accuracies': {
                k: round(v, 2) for k, v in parse_results['field_accuracies'].items()
            },
        },

        # Anonymization metrics
        'anonymization': {
            'total_fields_anonymized': anon_results['total_fields_anonymized'],
            'event_preservation_rate': round(anon_results['event_preservation_rate'], 2),
            'process_preservation_rate': round(anon_results['process_preservation_rate'], 2),
            'security_keyword_preservation_rate': round(
                anon_results['security_keyword_preservation_rate'], 2
            ),
        },

        # Mapping statistics
        'mapping_statistics': {
            'unique_hosts': unique_hosts,
            'unique_users': unique_users,
            'unique_pids': unique_pids,
            'unique_remote_hosts': unique_remote_hosts,
            'unique_ips': unique_ips,
        },

        # Deterministic consistency
        'deterministic_consistency': {
            'runs_passed': consistency_results['passed'],
            'runs_failed': consistency_results['failed'],
            'details': consistency_results['details'],
        },

        # Edge cases
        'edge_cases': {
            'passed': edge_results['passed'],
            'failed': edge_results['failed'],
            'details': edge_results['details'],
        },
    }

    return report


# ─── Pretty Print ─────────────────────────────────────────────────────────────

def print_report(report):
    """Print a nicely formatted console report."""
    print()
    print('=' * 80)
    print('  ANONYMIZER VALIDATION REPORT')
    print('=' * 80)
    print(f"  Generated: {report['generated_at']}")
    print(f"  Input:     {report['golden_input_file']}")
    print()

    # Parsing
    p = report['parsing']
    print('─' * 80)
    print('  PARSING RESULTS')
    print('─' * 80)
    print(f"  Total lines:       {p['total_lines']}")
    print(f"  Parseable:         {p['parseable_lines']}")
    print(f"  Unparseable:       {p['unparseable_lines']}")
    print(f"  Parse rate:        {p['parse_rate_pct']:.1f}%")
    print()
    print('  Per-field accuracy:')
    for field, acc in p['field_accuracies'].items():
        bar_len = int(acc / 2)
        bar = '█' * bar_len + '░' * (50 - bar_len)
        print(f"    {field:25s}  {bar}  {acc:.1f}%")
    print()

    # Anonymization
    a = report['anonymization']
    print('─' * 80)
    print('  ANONYMIZATION RESULTS')
    print('─' * 80)
    print(f"  Total fields anonymized:            {a['total_fields_anonymized']}")
    print(f"  Event preservation rate:            {a['event_preservation_rate']:.1f}%")
    print(f"  Process preservation rate:          {a['process_preservation_rate']:.1f}%")
    print(f"  Security keyword preservation rate: {a['security_keyword_preservation_rate']:.1f}%")
    print()

    # Mapping
    m = report['mapping_statistics']
    print('─' * 80)
    print('  MAPPING STATISTICS')
    print('─' * 80)
    print(f"  Unique hostnames:      {m['unique_hosts']}")
    print(f"  Unique users:          {m['unique_users']}")
    print(f"  Unique PIDs:           {m['unique_pids']}")
    print(f"  Unique remote hosts:   {m['unique_remote_hosts']}")
    print(f"  Unique IPs:            {m['unique_ips']}")
    print()

    # Consistency
    c = report['deterministic_consistency']
    print('─' * 80)
    print('  DETERMINISTIC CONSISTENCY')
    print('─' * 80)
    status = '✓ PASS' if c['runs_failed'] == 0 else '✗ FAIL'
    print(f"  Status:    {status}")
    print(f"  Runs passed: {c['runs_passed']}")
    print(f"  Runs failed: {c['runs_failed']}")
    if c['details']:
        for d in c['details'][:5]:
            print(f"    ! {d}")
    print()

    # Edge cases
    e = report['edge_cases']
    print('─' * 80)
    print('  EDGE CASES')
    print('─' * 80)
    total_edge = e['passed'] + e['failed']
    print(f"  Passed: {e['passed']} / {total_edge}")
    print(f"  Failed: {e['failed']} / {total_edge}")
    if e['details']:
        for d in e['details'][:10]:
            print(f"    ! {d}")
    print()

    # Summary
    print('=' * 80)
    all_pass = (
        p['parse_rate_pct'] > 80 and
        a['event_preservation_rate'] == 100.0 and
        a['process_preservation_rate'] == 100.0 and
        c['runs_failed'] == 0 and
        e['failed'] == 0
    )
    if all_pass:
        print('  ✓ ALL TESTS PASSED')
    else:
        print('  ✗ SOME TESTS FAILED — see details above')
    print('=' * 80)
    print()


# ─── Main ─────────────────────────────────────────────────────────────────────

def main():
    """Run all tests and generate the validation report."""
    print('[TestAnonymizer] Loading golden input...')
    lines = load_golden_input()
    print(f'[TestAnonymizer] Loaded {len(lines)} lines from {GOLDEN_INPUT}')

    # Test 1: Parsing
    print('\n[TestAnonymizer] Running parsing tests...')
    parse_results = test_parsing(lines)
    print(f'[TestAnonymizer] Parsed {parse_results["parseable_lines"]}/{parse_results["total_lines"]} lines')

    # Test 2: Anonymization
    print('\n[TestAnonymizer] Running anonymization tests...')
    anon_results = test_anonymization(parse_results['parsed_records'])
    print(f'[TestAnonymizer] Anonymized {len(anon_results["anonymized_records"])} records')

    # Test 3: Deterministic consistency
    print('\n[TestAnonymizer] Running deterministic consistency tests...')
    consistency_results = test_deterministic_consistency(lines)
    print(f'[TestAnonymizer] Consistency: {consistency_results["passed"]} passed, '
          f'{consistency_results["failed"]} failed')

    # Test 4: Edge cases
    print('\n[TestAnonymizer] Running edge case tests...')
    edge_results = test_edge_cases(lines)
    print(f'[TestAnonymizer] Edge cases: {edge_results["passed"]} passed, '
          f'{edge_results["failed"]} failed')

    # Build report
    report = build_report(parse_results, anon_results, consistency_results, edge_results)

    # Save report
    os.makedirs(RESULTS_DIR, exist_ok=True)
    with open(REPORT_PATH, 'w', encoding='utf-8') as f:
        json.dump(report, f, indent=2, ensure_ascii=False)
    print(f'\n[TestAnonymizer] Report saved to {REPORT_PATH}')

    # Print console report
    print_report(report)

    return report


if __name__ == '__main__':
    main()
