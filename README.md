# SLM-Log-Parser: Edge-Ready Anomaly Detection

![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)
![PyTorch](https://img.shields.io/badge/PyTorch-%23EE4C2C.svg?style=flat&logo=PyTorch&logoColor=white)
![HuggingFace](https://img.shields.io/badge/%F0%9F%A4%97%20Hugging%20Face-Transformers-blue)
![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)

## 📖 Executive Summary
This repository contains a complete, end-to-end machine learning pipeline for training a **Small Language Model (SLM)** to detect system anomalies directly from raw server logs. It is explicitly engineered for **Edge Devices and IoT** (such as the Raspberry Pi) operating under strict memory constraints (< 2GB RAM).

By utilizing **TinyLlama-1.1B** alongside **4-bit QLoRA adaptation**, this pipeline entirely bypasses the need for supervised labeled datasets. Instead, it relies on chronological temporal context windowing and a robust **Median Absolute Deviation (MAD) perplexity threshold** to perform completely unsupervised anomaly detection in real-world scenarios.

---

## 🛑 The Core Problem: Why Raw Logs Fail
Feeding raw system logs directly into an SLM or LLM leads to catastrophic failure and massive false-positive rates for two primary reasons:
1. **Token Noise**: Raw logs contain highly dynamic, unpredictable tokens (e.g., varying Process IDs like `sshd[20898]`, dynamic IP addresses, and differing timestamp formats like epoch vs. ISO-8601). These dynamic strings consume the SLM's limited context window and prevent the model from learning the true semantic patterns of normal system behavior.
2. **The "Labeled Data" Trap**: Traditional academic approaches (like the *LogLLM* architecture) rely on training supervised binary classifiers (Normal vs. Anomalous). In real-world enterprise or edge deployments, **labeled anomaly datasets do not exist**.

## 💡 The Solution Architecture (6-Stage Pipeline)
To solve these issues, we implemented a 6-stage pipeline that cleans, normalizes, trains, and evaluates logs without relying on a single pre-labeled anomaly.

### 1. Universal Streaming Log Parser (`src/universal_parser.py`)
A format-agnostic normalization engine that processes logs line-by-line (requiring virtually zero RAM). 
* **Auto-Detection**: Dynamically matches against Apache, Syslog, ISO-8601, HDFS, and BGL schemas.
* **Semantic Extraction**: Strips volatile timestamps and isolates the core semantic message and originating process.
* **Native Event Derivation**: Automatically categorizes raw messages into high-level events (e.g., `authentication_failure`, `session_opened`, `sudo_command`).

### 2. High-Speed PII Anonymization (`src/anonymizer.py`)
An ultra-fast, single-pass Regex engine that actively scrubs Personal Identifiable Information (PII) before the SLM ever sees it.
* **Reverse-Length-Order Masking**: Ensures that partial IP overlaps (e.g., `192.168.1.1` vs `192.168.1.100`) do not corrupt string replacement.
* **Pseudonymization**: Safely replaces variables with stable tokens (`REMOTE_HOST_001`, `USER_099`, `PID_042`) directly inside both the raw string and the metadata dictionary.

### 3. SLM Corpus Construction (`src/build_corpus.py`)
Converts the structured JSON output into compact text sequences optimized for transformer tokenization. Retains critical structural syntax (`process | event | metadata | message`) while reducing overall sequence token length by over 50%.

### 4. Unsupervised QLoRA Adaptation (`src/train_slm.py`)
The PyTorch training engine.
* **Temporal Windowing**: Groups sequential logs into 10-line chronological windows, teaching the SLM temporal behavioral flows (e.g., *session open $\rightarrow$ sudo command $\rightarrow$ session close*).
* **Quantization**: Loads TinyLlama in 4-bit (NF4) via `bitsandbytes`.
* **Constrained LoRA**: Applies low-rank adapters ($r=16, \alpha=32$) exclusively to attention matrices (`q_proj`, `v_proj`) to avoid catastrophic overfitting to the benign corpus.

### 5. MAD Anomaly Evaluation (`src/evaluate_slm.py`)
Instead of standard deviation, we use the mathematically robust **Median Absolute Deviation (MAD)** on validation sequence perplexities to establish the anomaly cutoff. 
* **Composite Injections**: The script programmatic splices realistic cyber-attacks (SSH bruteforcing, unauthorized closures, sudo abuse) into the center of true benign windows to verify if the model can detect sudden behavioral *shifts* in context.

### 6. Edge Deployment Export (`src/export_model.py`)
Merges the trained LoRA adapter weights directly into the TinyLlama base model, prepping the binary for `llama.cpp` GGUF conversion for Raspberry Pi deployment.

---

## 📊 Benchmark Results

### 1. Extraction Accuracy (LogPAI Benchmarks)
Tested against industry-standard 2,000-line datasets:
* **HDFS (Hadoop Logs)**: 100.0% Parse Rate
* **BGL (Supercomputer)**: 100.0% Parse Rate
* **Apache (Error Logs)**: 100.0% Parse Rate
* **Linux (Syslog/Auth)**: 100.0% Parse Rate

### 2. Token Reduction
By anonymizing and dropping noisy metadata, sequence length was reduced drastically. A standard 10-line authentication window dropped from ~200 tokens to a **p95 length of 57 tokens**, comfortably allowing temporal grouping within TinyLlama's context window.

---

## 📁 Detailed Repository Structure

```text
├── data/
│   ├── raw/                 # Raw datasets (LogPAI _2k samples, auth.log)
│   ├── parsed/              # JSON outputs of the Parser & Anonymizer
│   │   ├── auth_anonymized.ndjson.gz  # 650k lines, compressed
│   │   └── anonymization_map.json     # PII to Token mapping dictionary
│   └── corpus/              # SLM-ready txt sequence variants
│       ├── auth/            # 650k dataset corpora (full, message_only, etc.)
│       └── linux_2k/        # 2k dataset corpora
├── src/
│   ├── universal_parser.py  # The streaming log parser engine
│   ├── anonymizer.py        # The Regex PII masker
│   ├── build_corpus.py      # SLM text sequence generator
│   ├── train_slm.py         # TinyLlama QLoRA PyTorch training loop
│   ├── evaluate_slm.py      # MAD Thresholding & Perplexity scoring
│   └── export_model.py      # LoRA weight merging script
├── results/                 # Raw logs from benchmark tests
└── README.md
```

---

## 🚀 Installation & Setup

### Environment Requirements
If you are running this on a **Google Colab**, or **Kaggle** (Tesla T4 or better recommended), install the required dependencies:

```bash
# Clone the repository
git clone https://github.com/likkisamarthreddy/SLM-Log-Parser.git
cd SLM-Log-Parser

# Create an isolated environment (Optional)
python3 -m venv log_env
source log_env/bin/activate

# Install PyTorch & HuggingFace ML stack
pip install torch torchvision torchaudio --index-url https://download.pytorch.org/whl/cu118
pip install transformers peft bitsandbytes datasets accelerate evaluate
```

---

## 💻 Full Pipeline Usage Guide

You can run the entire pipeline from raw log to Raspberry-Pi-ready model using the following commands:

### Step 1: Parse and Anonymize
Pass your raw `.log` file into the parser. The `--anonymize` flag ensures PII is immediately scrubbed.
```bash
python src/universal_parser.py data/raw/auth.log -o data/parsed/auth_anonymized.json --anonymize
```

### Step 2: Build the SLM Corpus
Convert the JSON into text sequences optimized for the SLM context window.
```bash
python src/build_corpus.py --input data/parsed/auth_anonymized.json --output_dir data/corpus/auth/
```

### Step 3: Train the Model (Causal LM Adaptation)
Train the SLM on the `full` variant corpus. The script automatically handles 4-bit loading, 10-line temporal window grouping, and chronological 80/20 splitting.
```bash
python src/train_slm.py --corpus data/corpus/auth/corpus_full.txt
```

### Step 4: Evaluate Anomaly Detection
Once training is complete (the model is saved to `models/tinyllama_log_anomaly/best_model`), run the evaluation. This injects synthetic anomalies and calculates the MAD threshold.
```bash
python src/evaluate_slm.py --corpus data/corpus/auth/corpus_full.txt
```
*The script will output Precision/Recall/F1 metrics alongside a qualitative audit of the highest, lowest, and boundary-zone perplexity sequences.*

### Step 5: Export for Edge Deployment
Merge the trained LoRA adapters into the base model so it can be exported to GGUF format for IoT devices.
```bash
# Merge weights
python src/export_model.py

# Convert to GGUF (Requires cloning the generic llama.cpp repository)
python /path/to/llama.cpp/convert_hf_to_gguf.py models/tinyllama_log_anomaly/merged_model --outfile tinyllama_anomaly.gguf --outtype q4_k_m
```
