import os
import json
import argparse
from typing import Dict, Any, List, Optional
from collections import Counter
import time

def parse_args():
    parser = argparse.ArgumentParser(description="Build SLM-ready corpus sequences from anonymized logs")
    parser.add_argument("input", help="Path to anonymized JSON or NDJSON file")
    parser.add_argument("-o", "--output-dir", required=True, help="Output directory for the corpus txt files")
    parser.add_argument("--stats", action="store_true", help="Compute token statistics using TinyLlama tokenizer")
    return parser.parse_args()

def stream_logs(filepath: str):
    with open(filepath, "r", encoding="utf-8") as f:
        try:
            data = json.load(f)
            logs = data.get("logs", [])
            for log in logs:
                yield log
            return
        except json.JSONDecodeError:
            f.seek(0)
            for line in f:
                line = line.strip()
                if not line: continue
                # Skip metadata lines if any
                try:
                    obj = json.loads(line)
                    if "message" in obj:
                        yield obj
                except json.JSONDecodeError:
                    pass

def format_metadata(meta: Dict[str, Any]) -> str:
    if not meta:
        return ""
    # Filter out empty strings or Nones
    parts = []
    for k, v in meta.items():
        if v is not None and v != "":
            parts.append(f"{k}={v}")
    return " ".join(parts)

def generate_sequences(log: Dict[str, Any]) -> Dict[str, str]:
    process = str(log.get("process") or "unknown")
    event = str(log.get("event") or "unknown")
    meta_str = format_metadata(log.get("metadata", {}))
    
    # We use the raw message, as the anonymizer saves the masked string to "message"
    message = log.get("message", "").strip()
    
    # Format 1: message-only
    msg_only = message
    
    # Format 2: process-plus-message
    proc_msg = f"{process} : {message}"
    
    # Format 3: event-plus-message
    evt_msg = f"{event} : {message}"
    
    # Format 4: process-event-message-metadata
    full_parts = [process, event]
    if meta_str:
        full_parts.append(meta_str)
    full_parts.append(message)
    full_str = " | ".join(full_parts)
    
    return {
        "message_only": msg_only,
        "process_message": proc_msg,
        "event_message": evt_msg,
        "full": full_str,
        "raw_masked": log.get("masked_log", "").strip()
    }

def compute_stats(sequences: List[str], tokenizer) -> Dict[str, Any]:
    print("Computing token statistics...")
    t0 = time.time()
    
    total_tokens = 0
    token_counts = Counter()
    
    # Tokenize in batches for speed
    batch_size = 10000
    for i in range(0, len(sequences), batch_size):
        batch = sequences[i:i+batch_size]
        # Tokenize without padding, just get ids
        encodings = tokenizer(batch, add_special_tokens=False)
        for input_ids in encodings.input_ids:
            total_tokens += len(input_ids)
            for token_id in input_ids:
                token_counts[token_id] += 1
                
    elapsed = time.time() - t0
    
    unique_tokens = len(token_counts)
    rare_tokens = sum(1 for v in token_counts.values() if v < 5)
    
    return {
        "total_lines": len(sequences),
        "total_tokens": total_tokens,
        "unique_tokens": unique_tokens,
        "rare_tokens": rare_tokens,
        "avg_tokens_per_line": total_tokens / max(1, len(sequences)),
        "time_seconds": round(elapsed, 2)
    }

def main():
    args = parse_args()
    os.makedirs(args.output_dir, exist_ok=True)
    
    print(f"Reading logs from {args.input}...")
    
    corpora = {
        "message_only": [],
        "process_message": [],
        "event_message": [],
        "full": [],
        "raw_masked": [] # for comparison with raw string tokenization
    }
    
    for log in stream_logs(args.input):
        seqs = generate_sequences(log)
        for k, v in seqs.items():
            if v:
                corpora[k].append(v)
                
    # Write files
    paths = {}
    for k, seqs in corpora.items():
        if k == "raw_masked":
            continue
        out_path = os.path.join(args.output_dir, f"corpus_{k}.txt")
        paths[k] = out_path
        with open(out_path, "w", encoding="utf-8") as f:
            for s in seqs:
                f.write(s + "\n")
        print(f"Saved {len(seqs)} lines to {out_path}")
        
    if args.stats:
        try:
            from transformers import AutoTokenizer
            print("\nLoading TinyLlama tokenizer...")
            tokenizer = AutoTokenizer.from_pretrained("TinyLlama/TinyLlama-1.1B-Chat-v1.0", use_fast=True)
            
            stats_report = {}
            print("\n--- Token Statistics ---")
            for k in ["raw_masked", "message_only", "process_message", "event_message", "full"]:
                print(f"\nAnalyzing '{k}'...")
                stats = compute_stats(corpora[k], tokenizer)
                stats_report[k] = stats
                
                print(f"  Total tokens:          {stats['total_tokens']:,}")
                print(f"  Unique tokens (vocab): {stats['unique_tokens']:,}")
                print(f"  Rare tokens (<5 occ.): {stats['rare_tokens']:,}")
                print(f"  Avg tokens per line:   {stats['avg_tokens_per_line']:.2f}")
                
            report_path = os.path.join(args.output_dir, "corpus_stats.json")
            with open(report_path, "w", encoding="utf-8") as f:
                json.dump(stats_report, f, indent=2)
            print(f"\nSaved stats report to {report_path}")
                
        except ImportError:
            print("\nError: 'transformers' library not installed. Cannot compute token stats.")

if __name__ == "__main__":
    main()
