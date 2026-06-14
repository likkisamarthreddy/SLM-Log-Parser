import os
import argparse
import torch
import numpy as np
import math
from transformers import AutoTokenizer, AutoModelForCausalLM
from peft import PeftModel
import json

def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("--model_path", default="models/tinyllama_log_anomaly/best_model")
    parser.add_argument("--corpus", default="data/corpus/auth/corpus_full.txt")
    parser.add_argument("--window_size", type=int, default=10)
    parser.add_argument("--k_mad", type=float, default=3.0, help="Multiplier for MAD threshold")
    parser.add_argument("--test_fraction", type=float, default=0.2, help="Fraction of data used for testing (should match training split)")
    parser.add_argument("--anomaly_ratio", type=float, default=0.1, help="Fraction of test set to inject anomalies into")
    return parser.parse_args()

def inject_ssh_bruteforce(benign_window):
    if len(benign_window) < 5: return benign_window
    mid = len(benign_window) // 2
    anomaly_lines = [
        f"sshd-session | authentication_failure | rhost=REMOTE_HOST_005 user=USER_001 uid=0 | Failed password for root from REMOTE_HOST_005 port 22 ssh2"
    ] * 8
    return benign_window[:mid-2] + anomaly_lines + benign_window[mid+2:]

def inject_sudo_abuse(benign_window):
    if len(benign_window) < 3: return benign_window
    mid = len(benign_window) // 2
    anomaly_lines = [
        f"sudo | sudo_command | user=USER_099 uid=1005 | USER_099 : TTY=pts/0 ; PWD=/home/USER_099 ; USER=root ; COMMAND=/bin/bash"
    ]
    return benign_window[:mid] + anomaly_lines + benign_window[mid+1:]

def inject_abnormal_session_close(benign_window):
    if len(benign_window) < 3: return benign_window
    mid = len(benign_window) // 2
    anomaly_lines = [
        f"systemd-logind | session_closed | session=999 | Session 999 logged out. Waiting for processes to exit.",
        f"systemd-logind | session_closed | session=999 | Failed to stop session 999, process still running."
    ]
    return benign_window[:mid] + anomaly_lines + benign_window[mid+1:]

def inject_suspicious_remote_host(benign_window):
    if len(benign_window) < 3: return benign_window
    mid = len(benign_window) // 2
    anomaly_lines = [
        f"sshd-session | authentication_success | rhost=REMOTE_HOST_999 user=USER_001 | Accepted publickey for root from REMOTE_HOST_999 port 55555 ssh2"
    ]
    return benign_window[:mid] + anomaly_lines + benign_window[mid+1:]

def inject_anomalies(test_seqs, anomaly_ratio):
    print(f"Injecting anomalies into {anomaly_ratio*100}% of test set...")
    labels = [0] * len(test_seqs) # 0 = benign, 1 = anomalous
    
    num_anomalies = int(len(test_seqs) * anomaly_ratio)
    anomaly_indices = np.random.choice(len(test_seqs), num_anomalies, replace=False)
    
    injectors = [
        inject_ssh_bruteforce,
        inject_sudo_abuse,
        inject_abnormal_session_close,
        inject_suspicious_remote_host
    ]
    
    for idx in anomaly_indices:
        seq_lines = test_seqs[idx].split("\n")
        injector = np.random.choice(injectors)
        anom_lines = injector(seq_lines)
        test_seqs[idx] = "\n".join(anom_lines)
        labels[idx] = 1
        
    return test_seqs, labels

def calculate_perplexity(model, tokenizer, sequence, device):
    inputs = tokenizer(sequence, return_tensors="pt", truncation=True, max_length=1024).to(device)
    with torch.no_grad():
        outputs = model(inputs.input_ids, labels=inputs.input_ids)
        loss = outputs.loss.item()
    try:
        return math.exp(loss)
    except OverflowError:
        return float('inf')

def calculate_mad(perplexities):
    median = np.median(perplexities)
    mad = np.median(np.abs(perplexities - median))
    return median, mad

def evaluate_metrics(labels, predictions):
    tp = sum(1 for l, p in zip(labels, predictions) if l == 1 and p == 1)
    tn = sum(1 for l, p in zip(labels, predictions) if l == 0 and p == 0)
    fp = sum(1 for l, p in zip(labels, predictions) if l == 0 and p == 1)
    fn = sum(1 for l, p in zip(labels, predictions) if l == 1 and p == 0)
    
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0
    
    return precision, recall, f1, fp, fn

def main():
    args = parse_args()
    
    device = "cuda" if torch.cuda.is_available() else "cpu"
    print(f"Using device: {device}")
    
    try:
        model_id = "TinyLlama/TinyLlama-1.1B-Chat-v1.0"
        tokenizer = AutoTokenizer.from_pretrained(model_id)
        base_model = AutoModelForCausalLM.from_pretrained(model_id, device_map=device)
        print(f"Loading LoRA adapter from {args.model_path}...")
        model = PeftModel.from_pretrained(base_model, args.model_path)
    except Exception as e:
        print(f"Warning: Could not load fine-tuned adapter from {args.model_path}: {e}")
        model_id = "TinyLlama/TinyLlama-1.1B-Chat-v1.0"
        tokenizer = AutoTokenizer.from_pretrained(model_id)
        model = AutoModelForCausalLM.from_pretrained(model_id, device_map=device)
    
    model.eval()
    
    print(f"Loading data from {args.corpus}...")
    with open(args.corpus, "r", encoding="utf-8") as f:
        lines = [line.strip() for line in f if line.strip()]
        
    sequences = []
    for i in range(0, len(lines), args.window_size):
        window = lines[i:i+args.window_size]
        if len(window) == args.window_size:
            sequences.append("\n".join(window))
            
    split_idx = int(len(sequences) * (1 - args.test_fraction))
    test_seqs = sequences[split_idx:]
    
    if device == "cpu":
        print("CPU detected. Slicing test set to 20 sequences for extremely fast local evaluation.")
        test_seqs = test_seqs[:20]
        
    test_seqs, labels = inject_anomalies(test_seqs, args.anomaly_ratio)
    
    print("Computing perplexities...")
    perplexities = []
    for i, seq in enumerate(test_seqs):
        ppl = calculate_perplexity(model, tokenizer, seq, device)
        perplexities.append(ppl)
        if (i+1) % 50 == 0:
            print(f"Processed {i+1}/{len(test_seqs)}")
            
    # Calculate MAD on benign samples
    benign_ppls = [ppl for ppl, label in zip(perplexities, labels) if label == 0]
    median, mad = calculate_mad(benign_ppls)
    threshold = median + args.k_mad * mad
    
    print(f"\n--- Threshold Calibration ---")
    print(f"Benign Median PPL: {median:.2f}")
    print(f"Benign MAD:        {mad:.2f}")
    print(f"Threshold (k={args.k_mad}): {threshold:.2f}")
    
    predictions = [1 if ppl > threshold else 0 for ppl in perplexities]
    precision, recall, f1, fp, fn = evaluate_metrics(labels, predictions)
    
    print(f"\n--- Performance Metrics ---")
    print(f"Precision: {precision:.4f}")
    print(f"Recall:    {recall:.4f}")
    print(f"F1-Score:  {f1:.4f}")
    print(f"False Positives: {fp}")
    print(f"False Negatives: {fn}")
    
    print("\n--- Qualitative Audit ---")
    # Top 10 highest
    sorted_indices = np.argsort(perplexities)[::-1]
    print("\n[Top 10 Highest Perplexity (Most Anomalous)]")
    for i in range(min(10, len(sorted_indices))):
        idx = sorted_indices[i]
        label_str = "ANOMALY" if labels[idx] == 1 else "BENIGN"
        print(f"  #{i+1} | PPL: {perplexities[idx]:.2f} | Label: {label_str}")
        print("  " + test_seqs[idx].replace("\n", "\n  "))
        print("-" * 40)
        
    # Bottom 10 lowest
    sorted_indices = np.argsort(perplexities)
    print("\n[Bottom 10 Lowest Perplexity (Most Normal)]")
    for i in range(min(10, len(sorted_indices))):
        idx = sorted_indices[i]
        label_str = "ANOMALY" if labels[idx] == 1 else "BENIGN"
        print(f"  #{i+1} | PPL: {perplexities[idx]:.2f} | Label: {label_str}")
        print("  " + test_seqs[idx].replace("\n", "\n  "))
        print("-" * 40)
        
    # Boundary zone (closest to threshold)
    dist_to_thresh = np.abs(np.array(perplexities) - threshold)
    boundary_indices = np.argsort(dist_to_thresh)[:10]
    print("\n[Boundary Zone (Closest to Threshold)]")
    for i, idx in enumerate(boundary_indices):
        label_str = "ANOMALY" if labels[idx] == 1 else "BENIGN"
        dist = perplexities[idx] - threshold
        print(f"  #{i+1} | PPL: {perplexities[idx]:.2f} (Dist: {dist:+.2f}) | Label: {label_str}")
        print("  " + test_seqs[idx].replace("\n", "\n  "))
        print("-" * 40)

if __name__ == "__main__":
    main()
