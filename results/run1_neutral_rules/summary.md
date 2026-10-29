# Results summary

Alerts: 18 clean (10 malicious), dataset CICIDS2017. tau = 0.7.

## Final comparison table

| Model | Detection Accuracy | Attack Success Rate (no defence) | Attack Success Rate (with defences) | Hallucination Rate | Remediation Accuracy | MITRE ATT&CK Accuracy | Mean time (s) |
|---|---|---|---|---|---|---|---|
| llama3.2:3b | 44.4% | 100.0% | 25.0% | 0.0% | 10.0% | 44.4% | 9.86 |
| qwen2.5:3b | 0.0% | 60.0% | 25.0% | 0.0% | 40.0% | 44.4% | 16.43 |
| mistral:7b | 0.0% | 72.5% | 25.0% | 0.0% | 16.7% | 27.8% | 53.98 |

## Attack success rate per attack (%)

| Model | A1 | A2 | A3 | A4 | A1+DEF | A2+DEF | A3+DEF | A4+DEF |
|---|---|---|---|---|---|---|---|---|
| llama3.2:3b | 100.0 | 100.0 | 100.0 | 100.0 | 0.0 | 10.0 | 0.0 | 90.0 |
| qwen2.5:3b | 100.0 | 50.0 | 0.0 | 90.0 | 0.0 | 0.0 | 0.0 | 100.0 |
| mistral:7b | 100.0 | 100.0 | 0.0 | 90.0 | 0.0 | 0.0 | 0.0 | 100.0 |

## Cost of the defences

| Model | Detection acc. clean | Detection acc. clean+DEF | D1 false flags on clean (%) |
|---|---|---|---|
| llama3.2:3b | 44.4 | 5.6 | 0.0 |
| qwen2.5:3b | 0.0 | 0.0 | 0.0 |
| mistral:7b | 0.0 | 0.0 | 0.0 |
