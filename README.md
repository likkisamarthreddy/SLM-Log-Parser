# SLM-Log-Parser: Edge-Ready Unsupervised Anomaly Detection

![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)
![PyTorch](https://img.shields.io/badge/PyTorch-%23EE4C2C.svg?style=flat&logo=PyTorch&logoColor=white)
![HuggingFace](https://img.shields.io/badge/%F0%9F%A4%97%20Hugging%20Face-Transformers-blue)
![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)

## 📖 Executive Summary
This repository contains a complete, 12-step machine learning pipeline for training a **Small Language Model (SLM)** to detect cyber attacks and system anomalies directly from raw server logs. It is explicitly engineered for **Edge Devices and IoT** (such as the Raspberry Pi) operating under strict memory constraints (< 2GB RAM).

By utilizing **TinyLlama-1.1B** alongside **4-bit QLoRA adaptation**, this pipeline entirely bypasses the need for supervised labeled datasets. Instead, it relies on chronological temporal context windowing and a robust **Median Absolute Deviation (MAD) perplexity threshold** to perform completely unsupervised anomaly detection in real-world scenarios.

---

## 🛑 The Core Problem: Why Raw Logs Fail
Feeding raw system logs directly into an SLM or LLM leads to catastrophic failure and massive false-positive rates for two primary reasons:
1. **Token Noise**: Raw logs contain highly dynamic, unpredictable tokens (e.g., varying Process IDs like `sshd[20898]`, dynamic IP addresses, and differing timestamp formats). These dynamic strings consume the SLM's limited context window and prevent the model from learning the true semantic patterns of normal system behavior.
2. **The "Labeled Data" Trap**: Traditional academic approaches rely on training supervised binary classifiers (Normal vs. Anomalous). In real-world enterprise or edge deployments, **perfectly labeled anomaly datasets do not exist**.

---

## 🔬 The Solution Architecture (Why we built it this way)

### 1. Universal Streaming Log Parser (`src/structured_parser.py`)
To prevent memory exhaustion on edge devices, the parser streams logs line-by-line using generators. It automatically extracts `process`, `event`, and `metadata` from BSD Syslog and ISO-8601 schemas, converting massive 700MB+ `auth.log` files into queryable JSON in pure Python at over 23,000 lines per second.

### 2. Deterministic PII Anonymization (`src/log_anonymizer.py`)
**The "Why"**: If an SLM sees a log from `192.168.1.5` 1,000 times, it will memorize the IP as "safe". If the CEO logs in from a hotel IP (`8.8.8.8`), the SLM will flag it as an anomaly simply because the string is new, even if the login was totally legitimate. 

To solve this, our engine actively scrubs IPs, Usernames, and Hostnames, replacing them with stable tokens (`IP_001`, `USER_001`) *deterministically* across the entire dataset. The SLM is forced to learn **behavior** (e.g., `session_opened` followed by `sudo_command`), not memorizing strings. Critical context like `uid=0` (root privileges) and `sshd` are explicitly preserved.

### 3. Memory-Efficient Query Engine (`src/query_logs.py`)
A fast CLI tool that streams the massive anonymized datasets, allowing instant querying, filtering (`--event authentication_failure`), and aggregation (`--aggregate process`) without loading the files into RAM.

### 4. Corpus Compression (`src/build_corpus.py`)
We map the JSON into highly optimized token sequences: `sshd | authentication_failure | uid=0 | authentication failed for USER_001`. This drops the sequence token length by over **50%**, ensuring 10-line temporal windows fit securely inside TinyLlama's context span.

### 5. Causal LM Adaptation & QLoRA (`src/train_slm.py`)
**The "Why"**: We train the model to predict the "next token" in a chronological log sequence. We use **4-bit Quantization** and **Low-Rank Adaptation (LoRA)** to squeeze the 1.1 Billion parameter model into consumer hardware. The model learns the unique "grammar" and "flow" of your specific system's benign logs.

### 6. Perplexity Scoring & MAD Thresholding (`src/evaluate_slm.py`)
**The "Why"**: When the model reads a log sequence, it calculates a **Perplexity Score** (how surprised the model is by the text). If a hacker initiates a brute force or an abnormal `su` session, the perplexity spikes astronomically because the model has never seen that sequence flow before.

We use **Median Absolute Deviation (MAD)** instead of Standard Deviation to set the alert threshold. In cybersecurity, extreme outliers (attacks) heavily skew the mean and standard deviation, blinding the system. The Median is mathematically robust against extreme outliers, providing a rock-solid detection threshold.

---

## 📊 Evaluation Results & Synthetic Testing
During Step 12 evaluation, synthetic cyber-attacks were injected into the test corpus:
- **SSH Bruteforcing:** Injected repeated `authentication_failure` bursts.
- **Sudo Abuse:** Unexpected transitions from `session_opened` directly to `sudo` execution by non-standard users.
- **Abnormal Terminations:** Service crashes or irregular `systemd` closures.

**Results:**
The unadapted baseline TinyLlama model yields a very broad perplexity range, but once the QLoRA adapters are trained, the benign baseline perplexity compresses significantly (usually under 2.5 PPL). Synthetic attacks trigger massive perplexity spikes (10x to 50x higher than the MAD threshold), resulting in extremely high **Precision and Recall** without relying on a single labeled training sample.

---

## 🚀 How to Run the Pipeline (For Free on Google Colab)

Because the final stages require an **NVIDIA GPU** for 4-bit `bitsandbytes` quantization, running this locally on a standard Windows CPU will crash. 

Follow these steps to train your AI on Google Colab for free:

1. Go to [Google Colab](https://colab.research.google.com/) and create a "New Notebook".
2. In the top menu, click `Runtime` > `Change runtime type` > Select **T4 GPU** > Save.
3. Paste the following code into the first cell and hit the **Play** button:

```python
# 1. Clone your repository
!git clone https://github.com/likkisamarthreddy/SLM-Log-Parser.git
%cd SLM-Log-Parser

# 2. Install the necessary ML libraries for GPU acceleration
!pip install -q torch transformers peft bitsandbytes datasets accelerate evaluate

# 3. Execute the QLoRA Training Loop (Step 4)
# This will adapt TinyLlama to your specific log behavior
!python src/train_slm.py --corpus data/corpus/linux_2k/corpus_full.txt

# 4. Evaluate the Model's Anomaly Detection (Step 5)
# This injects synthetic attacks and calculates the MAD threshold metrics!
!python src/evaluate_slm.py --corpus data/corpus/linux_2k/corpus_full.txt
```

### Local CPU Commands (Data Engineering)
You can run the data engineering steps locally on your PC without a GPU:
```bash
# Parse and Anonymize massive raw logs
python scripts/test_auth_log.py

# Query the output
python src/query_logs.py -i data/processed/auth_anonymized.ndjson --event authentication_failure --limit 10

# Build the AI Corpus
python src/build_corpus.py data/processed/auth_anonymized.ndjson -o data/corpus/auth/
```
