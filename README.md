# Linux Syslog Parser for SLM Anomaly Detection

## Project Overview
This repository contains a robust Python log parser (`universal_parser.py`) designed to structure raw Linux syslogs into a canonical JSON format. This parsing step is a critical pre-processing pipeline for performing Anomaly Detection using Small Language Models (SLMs) like TinyLlama or Phi-3-mini.

## The Problem
When performing Unsupervised Fine-Tuning (e.g., Causal Language Modeling) on system logs, passing raw text strings directly to an SLM often leads to a high false-positive rate. For example, testing a TinyLlama model directly on `Linux_2k.log` resulted in all 2,000 logs being flagged as anomalies. This occurs because the SLM gets confused by:
- Unknown or highly variable Process IDs (PIDs).
- Embedded key-value pairs (e.g., `uid=0`, `rhost=...`) which alter the token structure of otherwise normal events.
- Variability in the timestamp formats.

## The Solution
`universal_parser.py` implements a robust regex-based extraction pipeline that perfectly isolates the core `message` string from the variable metadata.

It transforms raw logs like this:
```text
Jun 15 02:04:59 combo sshd(pam_unix)[20898]: authentication failure; logname= uid=0 euid=0 tty=NODEVssh ruser= rhost=220-135-151-1.hinet-ip.hinet.net  user=root
```

Into a strictly structured JSON schema:
```json
{
  "timestamp": "Jun 15 02:04:59",
  "hostname": "combo",
  "process": "sshd",
  "component": "pam_unix",
  "pid": 20898,
  "message": "authentication failure",
  "metadata": {
    "logname": "",
    "uid": 0,
    "euid": 0,
    "tty": "NODEVssh",
    "ruser": "",
    "rhost": "220-135-151-1.hinet-ip.hinet.net",
    "user": "root"
  }
}
```

By passing only the clean `"message"` and `"process"` fields to the SLM, the model can accurately learn the semantic language of the system without being distracted by dynamic tokens (like PIDs or IP addresses).

## Files in this Repository
- `universal_parser.py`: The parsing engine.
- `Linux_2k.log`: The raw 2,000 line dataset from the Logpai loghub.
- `Linux_2k.parsed.json`: The fully parsed JSON output, ready for SLM ingestion.

## Usage
To regenerate the parsed dataset, simply run:
```bash
python universal_parser.py Linux_2k.log --format pretty
```
