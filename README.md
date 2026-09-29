<div align="center">



\# 🛡️ CredGuard



\### Credential \& MFA Exposure Auditor



\*A defensive security tool built from a real-world breach case study\*



!\[Python](https://img.shields.io/badge/Python-3.8+-3776AB?style=flat\&logo=python\&logoColor=white)

!\[License](https://img.shields.io/badge/License-MIT-green.svg)

!\[Status](https://img.shields.io/badge/Status-Active-brightgreen)



</div>



\---



\## 📖 Background



In 2024–2026, attackers linked to the group \*\*UNC5537\*\* breached \*\*165+ organizations\*\* and exposed the records of \*\*over 100 million people\*\* through Snowflake customer accounts. Connor Moucka pleaded guilty to the campaign in August 2026.



> 🚨 \*\*No vulnerability in the Snowflake platform was ever exploited.\*\*



The entire breach came down to two conditions:



| # | Root Cause |

|---|---|

| 1️⃣ | Old passwords, harvested years earlier by infostealer malware, that were \*\*never rotated\*\* |

| 2️⃣ | \*\*Multi-factor authentication (MFA)\*\* not enabled on the targeted accounts |



\*\*CredGuard checks for exactly those two conditions — so a defender can find them before an attacker does.\*\*



\---



\## ✨ Features



\### 🔍 `check-password`

Tests a password against the HaveIBeenPwned Pwned Passwords API using the \*\*k-anonymity\*\* model. Only the first 5 characters of the password's SHA-1 hash are ever sent over the network — the password itself, and even its full hash, \*\*never leave your machine\*\*.



\### 📋 `audit`

Scans a CSV of accounts and flags every one that:

\- ❌ has no MFA enabled

\- ⏰ is running on a password older than your rotation policy (default 180 days)

\- ⚠️ is already known to be exposed (e.g. from internal threat-intel feeds)



Each account gets a \*\*risk score\*\*, weighted toward missing MFA — the actual root cause of the Snowflake breach — and scaled by data sensitivity, so you know exactly what to fix first.



\---



\## 🚀 Installation



```bash

git clone https://github.com/mayurchavan2/credguard.git

cd credguard

pip install -r requirements.txt   # stdlib only — nothing to install

```



Requires \*\*Python 3.8+\*\*. No external dependencies.



\---



\## 💻 Usage



\### Check a single password for exposure



```bash

python credguard.py check-password

```



You'll be prompted for a password (input hidden). Nothing is stored or logged.



\### Audit an account roster



```bash

python credguard.py audit sample\_accounts.csv

```



Write a report to a file, or export as CSV:



```bash

python credguard.py audit accounts.csv --output report.md

python credguard.py audit accounts.csv --output report.csv --format csv

python credguard.py audit accounts.csv --rotation-days 90

```



\*\*Expected CSV columns:\*\* `username, email, mfa\_enabled, password\_age\_days, sensitivity, known\_exposure`



\---

\---



\## 🎯 Design Notes



\- ✅ \*\*No offensive functionality\*\* — never logs into any system, guesses credentials, or targets systems it doesn't own

\- ✅ \*\*Privacy-preserving by design\*\* — k-anonymity means no password is ever transmitted in full

\- ✅ \*\*Extensible\*\* — risk-weighting constants at the top of `credguard.py` are easy to tune



\---



\## 📜 License



MIT — see \[LICENSE](LICENSE)



\## 🎓 Case Study



This tool accompanies a case-study presentation on the Snowflake/UNC5537 breach (ethical hacking / cloud security coursework).



<div align="center">



\*\*Built to catch the same gap that took down 165 companies.\*\*



</div>

