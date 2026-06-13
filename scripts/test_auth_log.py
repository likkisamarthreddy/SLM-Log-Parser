import os
import sys
import json
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.structured_parser import parse_line, get_parse_stats
from src.log_anonymizer import LogAnonymizer

def main():
    print("=" * 80)
    print("Testing Structured Log Anonymization on auth.log")
    print("=" * 80)

    root_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    input_file = os.path.join(root_dir, 'data', 'raw', 'auth.log')
    out_dir = os.path.join(root_dir, 'data', 'processed')
    os.makedirs(out_dir, exist_ok=True)
    
    out_anon_ndjson = os.path.join(out_dir, 'auth_anonymized.ndjson')
    out_map = os.path.join(out_dir, 'auth_anonymization_map.json')
    out_failed = os.path.join(out_dir, 'auth_failed.log')

    if not os.path.exists(input_file):
        print(f"Error: Could not find {input_file}")
        return

    # Parse and Anonymize in a streaming fashion to handle the 77MB file efficiently
    print(f"\nProcessing {input_file} (Streaming Mode)")
    
    anonymizer = LogAnonymizer()
    parsed_count = 0
    failed_count = 0
    
    start_time = time.time()
    
    # We will only keep basic stats to avoid memory explosion, and write directly to ndjson
    events_found = set()
    processes_found = set()
    
    with open(input_file, 'r', errors='ignore') as fin, \
         open(out_anon_ndjson, 'w', encoding='utf-8') as fout, \
         open(out_failed, 'w', encoding='utf-8') as ffail:
         
        for line_num, line in enumerate(fin, start=1):
            record = parse_line(line, line_number=line_num)
            if record:
                parsed_count += 1
                events_found.add(record.get('event'))
                processes_found.add(record.get('process'))
                
                anon_record = anonymizer.anonymize_record(record)
                fout.write(json.dumps(anon_record, ensure_ascii=False) + '\n')
            else:
                failed_count += 1
                if failed_count <= 100:  # Save first 100 failed lines
                    ffail.write(line)
                
            # Print progress every 100,000 lines
            if line_num % 100000 == 0:
                print(f"  Processed {line_num:,} lines...")

    elapsed = time.time() - start_time
    total = parsed_count + failed_count
    
    print("\n--- Pipeline Complete ---")
    print(f"Time taken            : {elapsed:.2f} seconds")
    print(f"Total lines read      : {total:,}")
    print(f"Successfully parsed   : {parsed_count:,} ({(parsed_count/total*100):.2f}%)")
    print(f"Failed to parse       : {failed_count:,}")
    print(f"Unique Events         : {len(events_found)}")
    print(f"Unique Processes      : {len(processes_found)}")
    
    print("\n--- Anonymization Statistics ---")
    print(f"  unique_hosts_mapped           : {len(anonymizer.mappings['hosts']):,}")
    print(f"  unique_users_mapped           : {len(anonymizer.mappings['users']):,}")
    print(f"  unique_pids_mapped            : {len(anonymizer.mappings['pids']):,}")
    print(f"  unique_remote_hosts_mapped    : {len(anonymizer.mappings['remote_hosts']):,}")
    print(f"  unique_ips_mapped             : {len(anonymizer.mappings['ips']):,}")
    
    # Save the mapping file
    anonymizer.save_mapping(out_map)
    print(f"\nOutputs saved to:\n  - {out_anon_ndjson}\n  - {out_map}")

if __name__ == '__main__':
    main()
