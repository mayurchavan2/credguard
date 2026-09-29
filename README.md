\# CredGuard



\*\*Credential \& MFA Exposure Auditor\*\* — a defensive security tool built from a real-world case study.



\## Background



In 2024–2026, attackers linked to the group \*\*UNC5537\*\* breached \*\*165+ organizations\*\* and exposed the records of \*\*over 100 million people\*\* through Snowflake customer accounts — Connor Moucka pleaded guilty to the campaign in August 2026. Notably:



> \*\*No vulnerability in the Snowflake platform was ever exploited.\*\*



The entire breach came down to two conditions:

1\. Old passwords, harvested years earlier by infostealer malware, that were never rotated.

2\. Multi-factor authentication (MFA) not enabled on the targeted accounts.



CredGuard checks for exactly those two conditions, so a defender can find them before an attacker does.



\## Features



\- \*\*`check-password`\*\* — Tests a password against the HaveIBeenPwned Pwned Passwords API using the \*\*k-anonymity\*\* model. Only the first 5 characters of the password's SHA-1 hash are ever sent over the network — the password itself, and even its full hash, never leave your machine.

\- \*\*`audit`\*\* — Scans a CSV of accounts and flags every one that:

&#x20; - has no MFA enabled,

&#x20; - is running on a password older than your rotation policy (default 180 days), and/or

&#x20; - is already known to be exposed (e.g. from internal threat-intel or breach-monitoring feeds)



&#x20; Each account gets a \*\*risk score\*\*, weighted toward missing MFA (the actual root cause of the Snowflake breach) and scaled by data sensitivity, so you know exactly what to fix first.



\## Installation



```bash

git clone https://github.com/mayurchavan2/credguard.git

cd credguard

pip install -r requirements.txt   # stdlib only — nothing to install

```



Requires Python 3.8+. No external dependencies.



\## Usage



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

(`sensitivity` is one of `low / medium / high / critical`; `mfa\_enabled` and `known\_exposure` are `true`/`false`.)



A sample roster is included at `sample\_accounts.csv` — try it out:



```bash

python credguard.py audit sample\_accounts.csv

```



\## Design notes



\- \*\*No offensive functionality.\*\* CredGuard never attempts to log into any system, guess credentials, or interact with a target it doesn't own. It only evaluates data you already have (a password you supply, or an account roster you provide).

\- \*\*Privacy-preserving by design.\*\* The breach-exposure check uses k-anonymity so no password is ever transmitted in full.

\- \*\*Extensible.\*\* The risk-weighting constants at the top of `credguard.py` are easy to tune for your own environment or a specific assignment/rubric.



\## License



MIT — see LICENSE file.



\## Case study



This tool accompanies a case-study presentation on the Snowflake/UNC5537 breach (ethical hacking / cloud security coursework).

