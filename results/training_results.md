# TinyLlama Log Anomaly Detection - Initial Training Results

## Phase 1: Synthetic Dataset Training

Before attempting to classify real-world logs, the TinyLlama model was initially fine-tuned on a synthetic dataset of structured logs to evaluate its baseline anomaly detection capabilities. 

The SLM was trained using **Causal Language Modeling** with **LoRA (Low-Rank Adaptation)** to predict anomalous log patterns efficiently.

### Evaluation Metrics

The table below summarizes the model's performance on the synthetic test set:

| Metric | Score | Interpretation |
| :--- | :--- | :--- |
| **Accuracy** | 99.64% | Out of 2,220 log lines tested, only 8 were misclassified. |
| **Precision** | 99.61% | When the model flags something as an attack, it is correct 99.6% of the time. |
| **Recall** | 100.00% | The model caught every single one of the 2,020 attack log lines. Zero missed. |
| **F1 Score** | 99.80% | The harmonic mean of Precision and Recall — near perfect balance. |
| **ROC AUC** | 100.00% | Perfect separation between normal and anomalous distributions. |

### Conclusion & Next Steps

The model achieved near-perfect accuracy (99.64%) on the structured synthetic dataset. However, when subsequently tested on the raw `Linux_2k.log` dataset, the model encountered a severe drop in performance (flagging all 2,000 logs as anomalies). 

This regression was traced back to **format mismatches** and the presence of dynamic, unstructured tokens (such as PIDs and embedded key-value pairs) in the raw Linux syslogs. 

To resolve this, the `universal_parser.py` (included in this repository) was developed to structure raw logs into a canonical JSON format. The next phase involves evaluating the TinyLlama model on the newly parsed `Linux_2k.parsed.json` dataset to restore the high accuracy observed during Phase 1.
