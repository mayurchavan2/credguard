\# 🛡️ CredGuard



\### Credential \& MFA Exposure Auditor



\*A cybersecurity case study, paired with a hands-on credential/MFA auditing tool\*



!\[Python](https://img.shields.io/badge/Python-3.8+-3776AB?style=for-the-badge\&logo=python\&logoColor=white) !\[Breach](https://img.shields.io/badge/Records-100M+-D72638?style=for-the-badge) !\[License](https://img.shields.io/badge/License-MIT-blue?style=for-the-badge) !\[Status](https://img.shields.io/badge/Status-Complete-brightgreen?style=for-the-badge)



\---



\## 📖 Overview



In \*\*February–October 2024\*\*, attackers tracked as \*\*UNC5537\*\* breached \*\*165+ organizations\*\* — including AT\&T and Ticketmaster — through Snowflake customer accounts, exposing the records of \*\*over 100 million people\*\*. Connor Moucka pleaded guilty to running the campaign in August 2026.



> 🚨 \*\*No vulnerability in the Snowflake platform was ever exploited.\*\*



This repository contains a case-study breakdown of that breach, \*\*plus\*\* a working Python tool that audits for the exact two conditions that let the attackers in.



| 🎯 What happened | 🧩 Why it matters |

|---|---|

| Credentials stolen years earlier by infostealer malware | Identity, not infrastructure, is the modern attack surface |

| Passwords never rotated after exposure | Credential hygiene is a recurring, \*fixable\* thread across breaches |

| MFA not enabled on targeted accounts | A single missing second factor caused a 100M-record breach |

| Attackers logged in like legitimate users — no exploit needed | These are cheap, high-impact checks any team can run today |



\---



\## 📁 Repository Structure

.

├── credguard.py 🔐 Credential \& MFA exposure auditor (CLI tool)

├── sample\_accounts.csv 📋 Example account roster for the audit command

├── requirements.txt 📦 Dependencies (stdlib only)

├── LICENSE 📜 MIT License

└── README.md







\---



\## 🔐 Tool: Credential \& MFA Exposure Auditor



> The Snowflake breach's root cause wasn't a software flaw — it was exposed

> credentials and missing MFA. CredGuard audits exactly that risk, locally

> and safely.



\### ✨ Features



| Command | What it does |

|---|---|

| 🔎 `check-password` | Tests a password against HaveIBeenPwned using \*\*k-anonymity\*\* — only the first 5 hash characters are sent; your real password never leaves your machine |

| 📋 `audit` | Scans a CSV roster and flags every account missing MFA, running stale credentials, or already known to be exposed — ranked by risk score |



📦 \*\*Zero third-party dependencies\*\* — Python standard library only.



\### 🚀 Installation



```bash

git clone https://github.com/mayurchavan2/credguard.git

cd credguard

pip install -r requirements.txt   # nothing to install — stdlib only

```



\### 💻 Usage



```bash

\# Check a single password (input hidden, never stored)

python credguard.py check-password



\# Audit an account roster

python credguard.py audit sample\_accounts.csv



\# Export as CSV / set a custom rotation policy

python credguard.py audit accounts.csv --output report.csv --format csv

python credguard.py audit accounts.csv --rotation-days 90

```



\*\*Expected CSV columns:\*\* `username, email, mfa\_enabled, password\_age\_days, sensitivity, known\_exposure`



\### 🖥️ Sample Output





Risk	Username	Sensitivity	                          Findings

142.5	jsmith	        critical	        No MFA enabled; Credentials found in known breach data; stale (410d)

96.0	avargas  	high	                 No MFA enabled; Credentials found in known breach data

0.0	mchen	        high	                          No issues found





\---



\## 🎯 Design Notes



| Principle | How CredGuard delivers it |

|---|---|

| \*\*No offensive functionality\*\* | Never logs into any system, guesses credentials, or targets accounts it doesn't own |

| \*\*Privacy-preserving by design\*\* | k-anonymity means no password is ever transmitted in full |

| \*\*Extensible\*\* | Risk-weighting constants at the top of `credguard.py` are easy to tune for your own rubric |



\---



\## 📚 References



\- The Hacker News — \*Snowflake Hacker Pleads Guilty\*, August 2026

\- BleepingComputer — \*Canadian pleads guilty to Snowflake cloud data-theft attacks\*, August 2026

\- Mandiant / Google Cloud — UNC5537 threat research

\- Have I Been Pwned — Pwned Passwords API documentation (k-anonymity model)



\---



\## 📜 License



MIT — see \[LICENSE](LICENSE)



\*Prepared as cybersecurity coursework 🎓 — built to catch the same gap that took down 165 companies.\*

