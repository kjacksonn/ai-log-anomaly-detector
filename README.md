# AI Log Anomaly Detector

An AI-assisted security project that analyzes Linux authentication logs and identifies suspicious login behavior using machine learning–based anomaly detection. This project simulates how Security Operations Center (SOC) teams detect unusual authentication activity such as brute-force attempts, invalid user access, and off-hours privileged logins.

---

## 🔍 Problem
Modern systems generate thousands of authentication events daily. Manually reviewing logs for suspicious behavior is inefficient and error-prone. SOC teams rely on anomaly detection techniques to surface events that deviate from normal patterns.

This project applies unsupervised machine learning to highlight potentially malicious authentication activity.

---

## 🧠 How It Works
1. Parses Linux-style `auth.log` authentication events
2. Extracts security-relevant features:
   - Login hour
   - Failed vs accepted logins
   - Invalid user attempts
   - User and IP frequency
   - Rolling failed attempts per IP
3. Trains an **Isolation Forest** model to identify anomalous events
4. Flags statistically unusual login activity for review

---

## 🚨 Example Detected Anomalies
- Invalid user enumeration attempts (e.g., `postgres`)
- Off-hours privileged account logins (`root`)
- Rare IP and user access patterns

Detected anomalies are exported to `output/anomalies.csv` for analysis.

---

## 🧰 Technologies Used
- Python
- Pandas
- Scikit-learn
- Isolation Forest
- Linux authentication log formats

---

## 🛡 MITRE ATT&CK Mapping
| Technique | Description |
|---------|-------------|
| T1110 | Brute Force |
| T1078 | Valid Accounts |
| T1033 | Account Discovery |

---

## ▶️ How to Run
```bash
python -m venv .venv
.venv\Scripts\activate
pip install pandas scikit-learn
python src/detect_anomalies.py
