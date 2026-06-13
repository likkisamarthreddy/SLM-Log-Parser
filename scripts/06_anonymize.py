import os
import sys
import json

# Add project root to sys.path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.structured_parser import parse_file, get_parse_stats
from src.log_anonymizer import LogAnonymizer

def main():
    print("=" * 80)
    print("Structured Log Anonymization Pipeline")
    print("=" * 80)

    # 1. Paths
    root_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    input_file = os.path.join(root_dir, 'data', 'logpai', 'Linux_2k.log')
    out_dir = os.path.join(root_dir, 'data', 'processed')
    os.makedirs(out_dir, exist_ok=True)
    
    out_parsed_json = os.path.join(out_dir, 'linux_2k_parsed.json')
    out_parsed_ndjson = os.path.join(out_dir, 'linux_2k_parsed.ndjson')
    out_anon_json = os.path.join(out_dir, 'linux_2k_anonymized.json')
    out_anon_ndjson = os.path.join(out_dir, 'linux_2k_anonymized.ndjson')
    out_map = os.path.join(out_dir, 'anonymization_map.json')

    # 2. Parse
    print("\n--- Parsing Phase ---")
    parsed_records = parse_file(input_file)
    parse_stats = get_parse_stats(parsed_records)
    print(f"Total lines parsed: {parse_stats['parsed_lines']}")
    print(f"Unique events found: {len(parse_stats['events_found'])}")
    print(f"Unique processes found: {len(parse_stats['processes_found'])}")

    # Save parsed
    with open(out_parsed_json, 'w', encoding='utf-8') as f:
        json.dump(parsed_records, f, indent=2)
    with open(out_parsed_ndjson, 'w', encoding='utf-8') as f:
        for r in parsed_records:
            f.write(json.dumps(r) + '\n')
            
    # 3. Anonymize
    print("\n--- Anonymization Phase ---")
    anonymizer = LogAnonymizer()
    anonymized_records = anonymizer.anonymize_file(parsed_records)
    
    # Save anonymized
    anonymizer.save_anonymized_json(anonymized_records, out_anon_json)
    anonymizer.save_anonymized_ndjson(anonymized_records, out_anon_ndjson)
    anonymizer.save_mapping(out_map)
    
    # 4. Stats
    print("\n--- Anonymization Statistics ---")
    anon_stats = anonymizer.get_anonymization_stats(parsed_records, anonymized_records)
    for k, v in anon_stats.items():
        print(f"  {k:30s}: {v}")

    # 5. Token Statistics
    print("\n--- Token Reduction Statistics ---")
    raw_tokens = set()
    anon_tokens = set()
    total_raw_len = 0
    total_anon_len = 0
    
    for r, a in zip(parsed_records, anonymized_records):
        rm_tokens = r['message'].split()
        am_tokens = a['message'].split()
        raw_tokens.update(rm_tokens)
        anon_tokens.update(am_tokens)
        total_raw_len += len(r['message'])
        total_anon_len += len(a['message'])
        
    print(f"  Unique tokens (Raw)         : {len(raw_tokens)}")
    print(f"  Unique tokens (Anonymized)  : {len(anon_tokens)}")
    vocab_reduction = (1 - len(anon_tokens) / len(raw_tokens)) * 100 if len(raw_tokens) > 0 else 0
    print(f"  Vocabulary Reduction        : {vocab_reduction:.2f}%")
    
    avg_raw_len = total_raw_len / len(parsed_records) if parsed_records else 0
    avg_anon_len = total_anon_len / len(anonymized_records) if anonymized_records else 0
    print(f"  Avg Msg Length (Raw)        : {avg_raw_len:.1f} chars")
    print(f"  Avg Msg Length (Anonymized) : {avg_anon_len:.1f} chars")

    # 6. Sample Comparison
    print("\n--- Sample Comparison ---")
    for i in range(min(5, len(parsed_records))):
        print(f"\nSample {i+1}:")
        print(f"  Raw   : {parsed_records[i]['raw_log']}")
        print(f"  Masked: {anonymized_records[i]['masked_log']}")

if __name__ == '__main__':
    main()
