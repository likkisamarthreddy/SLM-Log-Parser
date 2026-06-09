import os
import sys
import json
import csv
import argparse
from collections import Counter
from typing import List, Dict, Any

def parse_args():
    parser = argparse.ArgumentParser(description="Query Interface for Structured Log JSON")
    parser.add_argument("input", help="Path to parsed JSON or NDJSON file")
    
    # Filtering Arguments
    parser.add_argument("--process", help="Filter by process name (e.g., sshd, su)")
    parser.add_argument("--event", help="Filter by event type (e.g., authentication_failure)")
    parser.add_argument("--hostname", help="Filter by hostname")
    parser.add_argument("--pid", help="Filter by PID")
    parser.add_argument("--keyword", help="Substring match in the message field")
    parser.add_argument("--user", help="Filter by user (looks in metadata)")
    parser.add_argument("--rhost", help="Filter by rhost (looks in metadata)")
    parser.add_argument("--meta", action="append", help="Filter by arbitrary metadata (format: key=value)")

    # Aggregation
    parser.add_argument("--group-by", help="Aggregate and count by a specific field (process, event, user, hostname)")
    
    # Output
    parser.add_argument("--output", help="Save results to a file (.json or .csv)")
    parser.add_argument("--limit", type=int, help="Limit the number of results printed to console")

    return parser.parse_args()

def stream_logs(filepath: str):
    """Generator that yields one log dictionary at a time, handling both JSON array and NDJSON formats."""
    with open(filepath, "r", encoding="utf-8") as f:
        # First, try to read as a single JSON file
        try:
            data = json.load(f)
            logs = data.get("logs", [])
            for log in logs:
                yield log
            return  # Successfully read as standard JSON
        except json.JSONDecodeError:
            # If it fails, it's likely NDJSON, so we process line-by-line
            f.seek(0)
            for line in f:
                line = line.strip()
                if not line: continue
                try:
                    yield json.loads(line)
                except:
                    pass

def match_log(log: Dict[str, Any], args: argparse.Namespace, meta_filters: Dict[str, str]) -> bool:
    """Returns True if the log matches all given filters."""
    if args.process and log.get("process") != args.process: return False
    if args.event and log.get("event") != args.event: return False
    if args.hostname and log.get("hostname") != args.hostname: return False
    if args.pid and log.get("pid") != args.pid: return False
    
    if args.keyword and args.keyword.lower() not in log.get("message", "").lower():
        return False
        
    meta = log.get("metadata", {})
    if args.user and meta.get("user") != args.user: return False
    if args.rhost and meta.get("rhost") != args.rhost: return False
    
    for k, v in meta_filters.items():
        if str(meta.get(k, "")) != v:
            return False
            
    return True

def export_csv(results: List[Dict[str, Any]], filepath: str):
    if not results:
        print("No results to export.")
        return
        
    # Flatten metadata into main dictionary
    flat_results = []
    all_keys = set()
    
    for r in results:
        flat = {k: v for k, v in r.items() if k != "metadata"}
        meta = r.get("metadata", {})
        for k, v in meta.items():
            flat[f"meta_{k}"] = v
        for k in flat.keys():
            all_keys.add(k)
        flat_results.append(flat)
        
    with open(filepath, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(all_keys))
        writer.writeheader()
        writer.writerows(flat_results)

def main():
    args = parse_args()
    
    if not os.path.exists(args.input):
        print(f"File not found: {args.input}")
        return

    # Parse metadata filters
    meta_filters = {}
    if args.meta:
        for m in args.meta:
            if "=" in m:
                k, v = m.split("=", 1)
                meta_filters[k] = v

    results = []
    counter = Counter()

    print(f"Reading logs from {args.input}...")
    for log in stream_logs(args.input):
        if match_log(log, args, meta_filters):
            results.append(log)
            if args.group_by:
                # Grouping extraction logic
                if args.group_by in ["user", "rhost", "uid", "euid", "tty", "exit_code"]:
                    val = log.get("metadata", {}).get(args.group_by, "UNKNOWN")
                else:
                    val = log.get(args.group_by, "UNKNOWN")
                counter[val] += 1

    print(f"\nMatched {len(results)} logs.")

    if args.group_by:
        print(f"\n--- Aggregation by '{args.group_by}' ---")
        print(f"{args.group_by.upper().ljust(30)} COUNT")
        print("-" * 45)
        for val, count in counter.most_common():
            print(f"{str(val).ljust(30)} {count}")
    else:
        # Print sample results
        limit = args.limit if args.limit else 5
        if results:
            print("\n--- Sample Matches ---")
            for r in results[:limit]:
                ts = r.get("timestamp", "")
                proc = r.get("process", "unknown")
                evt = r.get("event", "unknown")
                msg = r.get("message", "")
                print(f"[{ts}] {proc} ({evt}): {msg}")

    # Output export
    if args.output:
        os.makedirs(os.path.dirname(os.path.abspath(args.output)), exist_ok=True)
        if args.output.endswith(".csv"):
            export_csv(results, args.output)
            print(f"\nExported {len(results)} rows to {args.output}")
        else:
            with open(args.output, "w", encoding="utf-8") as f:
                json.dump(results, f, indent=2)
            print(f"\nExported {len(results)} rows to {args.output}")

if __name__ == "__main__":
    main()
