import os
import json
import argparse
import csv
from collections import Counter
from typing import Iterator, Dict, Any

def parse_args():
    parser = argparse.ArgumentParser(description="Query and Aggregate Structured Log JSON/NDJSON files using memory-efficient streaming.")
    
    # Input
    parser.add_argument("-i", "--input", required=True, help="Path to parsed/anonymized JSON or NDJSON log file")
    
    # Filters
    parser.add_argument("--process", help="Filter by process name (e.g., sshd, su)")
    parser.add_argument("--event", help="Filter by event type (e.g., authentication_failure)")
    parser.add_argument("--hostname", help="Filter by hostname")
    parser.add_argument("--pid", help="Filter by PID")
    parser.add_argument("--user", help="Shortcut to filter by metadata 'user'")
    parser.add_argument("--rhost", help="Shortcut to filter by metadata 'rhost'")
    parser.add_argument("--message-contains", help="Filter logs where message contains this substring")
    parser.add_argument("--meta", nargs="+", help="Filter by metadata key=value pairs (e.g., --meta uid=0 exit_code=1)")
    
    # Execution Modifiers
    parser.add_argument("--limit", type=int, default=100, help="Max number of results to display/export (default: 100, 0 for unlimited)")
    
    # Aggregation
    parser.add_argument("--aggregate", choices=["process", "event", "user", "hostname", "hour"], help="Perform a count aggregation instead of listing logs")
    
    # Export
    parser.add_argument("--export-json", help="Path to save output as JSON array")
    parser.add_argument("--export-csv", help="Path to save output as CSV")
    
    return parser.parse_args()

def parse_metadata_filters(meta_args: list) -> Dict[str, str]:
    meta_filters = {}
    if meta_args:
        for arg in meta_args:
            if "=" in arg:
                k, v = arg.split("=", 1)
                meta_filters[k] = v
    return meta_filters

def stream_records(filepath: str) -> Iterator[Dict[str, Any]]:
    """Yields log records one by one from NDJSON or JSON array."""
    with open(filepath, 'r', encoding='utf-8') as f:
        # Try to read the first character to determine format
        first_char = f.read(1)
        f.seek(0)
        
        if first_char == '[':
            # It's a standard JSON array (load entirely to memory, unfortunately necessary for array without ijson)
            try:
                data = json.load(f)
                for record in data:
                    yield record
            except Exception as e:
                print(f"Error loading JSON array: {e}")
        else:
            # Assume NDJSON - highly efficient streaming
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    yield json.loads(line)
                except json.JSONDecodeError:
                    continue

def record_matches(record: Dict[str, Any], args: argparse.Namespace, meta_filters: Dict[str, str]) -> bool:
    """Returns True if the record matches all provided filters."""
    if args.process and record.get('process') != args.process:
        return False
    if args.event and record.get('event') != args.event:
        return False
    if args.hostname and record.get('hostname') != args.hostname:
        return False
    if args.pid and str(record.get('pid')) != str(args.pid):
        return False
        
    # Metadata filters
    meta = record.get('metadata', {})
    if args.user and str(meta.get('user')) != args.user:
        return False
    if args.rhost and str(meta.get('rhost')) != args.rhost:
        return False
        
    for k, v in meta_filters.items():
        if str(meta.get(k)) != v:
            return False
            
    # Substring search
    if args.message_contains and args.message_contains.lower() not in record.get('message', '').lower():
        return False
        
    return True

def print_record(record: Dict[str, Any]):
    """Pretty print a single log record."""
    ts = record.get('timestamp', '')
    host = record.get('hostname', '')
    proc = record.get('process', '')
    evt = record.get('event', '')
    msg = record.get('message', '')
    meta = record.get('metadata', {})
    
    meta_str = " ".join([f"{k}={v}" for k, v in meta.items()])
    print(f"[{ts}] {host} | {proc} | {evt} | {msg} | {meta_str}")

def export_to_json(data: list, filepath: str):
    with open(filepath, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2)
    print(f"Exported {len(data)} items to {filepath}")

def export_to_csv(data: list, filepath: str, is_aggregation: bool):
    with open(filepath, 'w', encoding='utf-8', newline='') as f:
        if is_aggregation:
            writer = csv.writer(f)
            writer.writerow(["Key", "Count"])
            for row in data:
                writer.writerow([row["key"], row["count"]])
        else:
            if not data:
                return
            # Collect all possible keys
            keys = set()
            for r in data:
                keys.update(r.keys())
                if 'metadata' in r:
                    keys.update([f"meta.{k}" for k in r['metadata'].keys()])
            keys.discard('metadata')
            key_list = sorted(list(keys))
            
            writer = csv.DictWriter(f, fieldnames=key_list)
            writer.writeheader()
            
            for r in data:
                flat_r = {k: v for k, v in r.items() if k != 'metadata'}
                for k, v in r.get('metadata', {}).items():
                    flat_r[f"meta.{k}"] = v
                writer.writerow(flat_r)
    print(f"Exported {len(data)} items to {filepath}")

def main():
    args = parse_args()
    meta_filters = parse_metadata_filters(args.meta)
    
    if not os.path.exists(args.input):
        print(f"File not found: {args.input}")
        return

    print(f"Querying {args.input} (Streaming mode)...")
    
    matched_records = []
    aggregation_counter = Counter()
    match_count = 0
    
    for record in stream_records(args.input):
        if record_matches(record, args, meta_filters):
            match_count += 1
            
            if args.aggregate:
                if args.aggregate == "process":
                    key = record.get('process', 'unknown')
                elif args.aggregate == "event":
                    key = record.get('event', 'unknown')
                elif args.aggregate == "user":
                    key = record.get('metadata', {}).get('user', 'unknown')
                elif args.aggregate == "hostname":
                    key = record.get('hostname', 'unknown')
                elif args.aggregate == "hour":
                    ts = record.get('timestamp', '')
                    if 'T' in ts:  # ISO
                        key = ts.split('T')[1].split(':')[0]
                    else:  # BSD
                        parts = ts.split()
                        if len(parts) >= 3:
                            key = parts[2].split(':')[0]
                        else:
                            key = "unknown"
                
                aggregation_counter[key] += 1
            else:
                if args.limit == 0 or len(matched_records) < args.limit:
                    matched_records.append(record)
                
    print(f"\n--- Query Complete ---")
    print(f"Total Matches Found: {match_count:,}")
    
    if args.aggregate:
        print(f"\nAggregation by {args.aggregate.upper()}:")
        agg_data = []
        for k, count in aggregation_counter.most_common(args.limit if args.limit > 0 else None):
            print(f"  {k:<30} : {count:,}")
            agg_data.append({"key": k, "count": count})
            
        if args.export_json:
            export_to_json(agg_data, args.export_json)
        if args.export_csv:
            export_to_csv(agg_data, args.export_csv, True)
            
    else:
        print(f"\nDisplaying Top {len(matched_records)} Results:")
        for r in matched_records:
            print_record(r)
            
        if args.export_json:
            export_to_json(matched_records, args.export_json)
        if args.export_csv:
            export_to_csv(matched_records, args.export_csv, False)

if __name__ == "__main__":
    main()
