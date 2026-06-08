# SLM-Log-Parser: Edge-Ready Anomaly Detection

## Project Overview
This repository contains a robust **Universal Log Parser** (`src/universal_parser.py`) and a testing framework designed to evaluate its accuracy on industry-standard datasets. 

This parser is the critical data-preprocessing pipeline for a **Small Language Model (SLM) based Log Anomaly Detection System**, specifically targeting **Edge Devices and IoT** (like the Raspberry Pi). We are utilizing **TinyLlama-1.1B** with LoRA adapters and INT4 quantization to achieve real-time anomaly detection within strict memory constraints (< 2GB RAM).

---

## 🎯 The Problem: Why not feed raw logs to an AI?
When performing Unsupervised Fine-Tuning or Causal Language Modeling on system logs, feeding raw strings directly to an SLM leads to massive false-positive rates (e.g., initial testing flagged 100% of normal logs as anomalies). 

This happens because raw logs contain highly dynamic, unpredictable tokens:
- **Variable Process IDs (PIDs)**: `sshd[20898]` vs `sshd[1023]`
- **Embedded Key-Value Pairs**: IPs, user IDs, and routing metadata
- **Varying Timestamp Formats**: Epoch, ISO-8601, BSD Syslog, etc.

These dynamic tokens severely confuse a small model like TinyLlama-1.1B, preventing it from learning the true semantic patterns of normal system behavior.

## 💡 The Solution: Universal Log Parsing
Instead of writing brittle, hard-coded parsers for every log format, `universal_parser.py` acts as a streaming, format-agnostic normalization engine. It evaluates incoming logs against multiple schemas (HDFS, Apache, Syslog, BGL) and **automatically isolates the core semantic message** from the dynamic metadata.

By stripping out variables (IPs, PIDs) and passing *only* the normalized `"message"` and `"process"` fields to the SLM, the model's accuracy drastically increases.

### Key Features:
- **Auto-Detection:** Automatically identifies formats like Apache, Syslog, HDFS, and BGL.
- **Self-Healing:** If a log format drifts (e.g., an Apache log drops its PID), the parser dynamically falls back to heuristic extraction to prevent pipeline failure.
- **Streaming Architecture:** Processes logs line-by-line, requiring almost zero RAM. Perfect for IoT.

---

## 📊 Benchmark Results (LogPAI)
To prove the reliability of the parser, it was benchmarked against four diverse 2,000-line datasets from the industry-standard **LogPAI** repository. The results prove the parser's flawless extraction capabilities:

1. **HDFS (Hadoop Logs)** - 100% Accuracy (`hdfs_log` format)
2. **BGL (Supercomputer)** - 100% Accuracy (`bgl_log` format)
3. **Apache (Error Logs)** - 100% Accuracy (`apache_error` format)
4. **Linux (Syslog)** - 100% Accuracy (`bsd_syslog` format)

*(Full testing logs can be found in `results/logpai_test_results.txt`)*

---

## 📁 Repository Structure
To keep the project clean and understandable, only essential pipeline code and results are tracked in this repository:

```text
├── data/
│   ├── raw/          # Raw 2k datasets from LogPAI (HDFS, BGL, Apache, Linux)
│   └── parsed/       # The heavily structured, cleanly parsed JSON outputs
├── src/
│   ├── universal_parser.py  # The core streaming log parser engine
│   ├── test_logpai.py       # Script used to benchmark the 4 datasets
│   └── test_live.py         # Live streaming evaluation script
├── results/
│   ├── logpai_test_results.txt  # Accuracy metrics across the 4 datasets
│   └── training_results.md      # SLM synthetic training metrics
└── README.md
```

## 🚀 Usage

**To run the LogPAI Benchmark Test:**
```bash
python src/test_logpai.py
```

**To manually parse a file and output pretty JSON:**
```bash
python src/universal_parser.py data/raw/Linux_2k.log -o data/parsed/Linux_2k.parsed.json --format pretty
```
