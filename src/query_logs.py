import argparse
import json
import csv
import sys
from collections import Counter
from typing import List, Dict, Any

def load_ndjson(filepath: str) -> List[Dict[str, Any]]:
    logs = []
    try:
        if filepath.endswith('.gz'):
            import gzip
            with gzip.open(filepath, 'rt', encoding='utf-8') as f:
                for line in f:
                    logs.append(json.loads(line))
        else:
            with open(filepath, 'r', encoding='utf-8') as f:
                for line in f:
                    logs.append(json.loads(line))
        # Skip the metadata line if it exists
        if logs and '_metadata' in logs[0]:
            return logs[1:]
        return logs
    except Exception as e:
        print(f"Error loading {filepath}: {e}")
        sys.exit(1)

def load_json(filepath: str) -> List[Dict[str, Any]]:
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            data = json.load(f)
            return data.get('logs', [])
    except Exception as e:
        print(f"Error loading {filepath}: {e}")
        sys.exit(1)

def filter_logs(logs: List[Dict[str, Any]], args) -> List[Dict[str, Any]]:
    filtered = []
    for log in logs:
        # Basic filtering
        if args.process and log.get('process') != args.process: continue
        if args.event and log.get('event') != args.event: continue
        if args.hostname and log.get('hostname') != args.hostname: continue
        if args.pid and str(log.get('pid')) != str(args.pid): continue
        if args.keyword and args.keyword.lower() not in log.get('message', '').lower(): continue
        
        # Metadata filtering
        meta = log.get('metadata', {})
        if args.user and meta.get('user') != args.user: continue
        if args.rhost and meta.get('rhost') != args.rhost: continue
        if args.uid is not None and str(meta.get('uid')) != str(args.uid): continue
        if args.tty and meta.get('tty') != args.tty: continue
        if args.exit_code is not None and str(meta.get('exit_code')) != str(args.exit_code): continue
        
        filtered.append(log)
    return filtered

def print_aggregations(logs: List[Dict[str, Any]], args):
    if not logs:
        print("No logs to aggregate.")
        return

    if args.count_by_process:
        print("\n--- Count by Process ---")
        counts = Counter(log.get('process') for log in logs if log.get('process'))
        for k, v in counts.most_common(10): print(f"{k}: {v}")

    if args.count_by_event:
        print("\n--- Count by Event ---")
        counts = Counter(log.get('event') for log in logs if log.get('event'))
        for k, v in counts.most_common(10): print(f"{k}: {v}")

    if args.count_by_user:
        print("\n--- Count by User ---")
        counts = Counter(log.get('metadata', {}).get('user') for log in logs if log.get('metadata', {}).get('user'))
        for k, v in counts.most_common(10): print(f"{k}: {v}")

    if args.count_by_hostname:
        print("\n--- Count by Hostname ---")
        counts = Counter(log.get('hostname') for log in logs if log.get('hostname'))
        for k, v in counts.most_common(10): print(f"{k}: {v}")

    if args.count_by_hour:
        print("\n--- Count by Hour ---")
        # Basic hour extraction assuming timestamp starts with Date/Time
        hours = []
        for log in logs:
            ts = log.get('timestamp')
            if ts:
                # Naive split for standard syslog "Jun 15 04:06:18" or ISO "2026-04-05T15:35:01"
                try:
                    if 'T' in ts:
                        hour = ts.split('T')[1].split(':')[0]
                    else:
                        hour = ts.split()[2].split(':')[0]
                    hours.append(hour)
                except Exception:
                    pass
        counts = Counter(hours)
        for k, v in sorted(counts.items()): print(f"{k}:00 -> {v}")

def export_results(logs: List[Dict[str, Any]], output_file: str, format: str):
    if format == 'json':
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump({"logs": logs}, f, indent=2)
        print(f"\nExported {len(logs)} records to {output_file}")
    elif format == 'csv':
        if not logs:
            print("No logs to export.")
            return
        # Flatten basic fields
        headers = ['line_number', 'timestamp', 'hostname', 'process', 'pid', 'event', 'message']
        with open(output_file, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=headers, extrasaction='ignore')
            writer.writeheader()
            for log in logs:
                row = {k: log.get(k) for k in headers}
                writer.writerow(row)
        print(f"\nExported {len(logs)} records to {output_file}")

def main():
    parser = argparse.ArgumentParser(description="Query and Aggregate Structured JSON Logs")
    
    # Input/Output
    parser.add_argument('--input', required=True, help='Path to parsed JSON or NDJSON file')
    parser.add_argument('--export', help='Path to export results')
    parser.add_argument('--format', choices=['json', 'csv'], default='json', help='Export format (default: json)')
    
    # Basic Filters
    parser.add_argument('--process', help='Filter by process name (e.g. sshd)')
    parser.add_argument('--event', help='Filter by event type (e.g. authentication_failure)')
    parser.add_argument('--hostname', help='Filter by hostname')
    parser.add_argument('--pid', help='Filter by PID')
    parser.add_argument('--keyword', help='Filter by substring in message')
    
    # Metadata Filters
    parser.add_argument('--user', help='Filter by metadata user')
    parser.add_argument('--uid', help='Filter by metadata uid')
    parser.add_argument('--rhost', help='Filter by metadata rhost')
    parser.add_argument('--tty', help='Filter by metadata tty')
    parser.add_argument('--exit_code', help='Filter by metadata exit_code')
    
    # Aggregations
    parser.add_argument('--count-by-process', action='store_true', help='Show top processes')
    parser.add_argument('--count-by-event', action='store_true', help='Show top events')
    parser.add_argument('--count-by-user', action='store_true', help='Show top users')
    parser.add_argument('--count-by-hostname', action='store_true', help='Show top hostnames')
    parser.add_argument('--count-by-hour', action='store_true', help='Show activity by hour')

    args = parser.parse_args()

    print(f"Loading {args.input}...")
    if args.input.endswith('.ndjson') or args.input.endswith('.ndjson.gz'):
        logs = load_ndjson(args.input)
    else:
        logs = load_json(args.input)
        
    print(f"Loaded {len(logs)} records.")

    filtered_logs = filter_logs(logs, args)
    print(f"Matched {len(filtered_logs)} records after filtering.")

    # Show a sample if filters were applied and no aggregations requested
    if len(filtered_logs) > 0 and len(filtered_logs) != len(logs):
        if not any([args.count_by_process, args.count_by_event, args.count_by_user, args.count_by_hostname, args.count_by_hour]):
            print("\nSample Match:")
            print(json.dumps(filtered_logs[0], indent=2))

    # Run Aggregations
    print_aggregations(filtered_logs, args)

    # Export
    if args.export:
        export_results(filtered_logs, args.export, args.format)

if __name__ == "__main__":
    main()
