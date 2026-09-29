#!/usr/bin/env python3
"""
CredGuard - Credential & MFA Exposure Auditor
===============================================

Born from the Snowflake / UNC5537 breach (2024-2026): 165+ organizations
compromised with ZERO platform vulnerabilities exploited. Attackers simply
logged in with old, leaked passwords on accounts that had no MFA enabled.

CredGuard checks for exactly those two conditions before an attacker does:

  1. check-password : Is a password known to be exposed in a breach?
                       Uses the HaveIBeenPwned Pwned Passwords API with
                       k-anonymity - your password (or its full hash) is
                       NEVER sent over the network.

  2. audit           : Scan an account roster (CSV) for accounts missing
                       MFA, running on stale (un-rotated) credentials, or
                       already flagged as exposed by threat intel - and
                       rank them by risk so you know what to fix first.

Usage:
    python credguard.py check-password
    python credguard.py audit accounts.csv --output report.md
    python credguard.py audit accounts.csv --output report.csv --format csv

No credentials are ever stored, logged, or transmitted in full by this tool.
"""

import argparse
import csv
import getpass
import hashlib
import sys
import urllib.request
import urllib.error
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional


HIBP_RANGE_URL = "https://api.pwnedpasswords.com/range/{prefix}"

# Risk weights - tuned around the Snowflake breach's actual root cause:
# missing MFA was the single point of failure, so it dominates the score.
WEIGHT_NO_MFA = 50
WEIGHT_KNOWN_EXPOSURE = 30
WEIGHT_STALE_CREDENTIAL = 15
DEFAULT_ROTATION_DAYS = 180

SENSITIVITY_MULTIPLIER = {
    "critical": 1.5,
    "high": 1.2,
    "medium": 1.0,
    "low": 0.7,
}


# --------------------------------------------------------------------------
# 1. Breach-exposure check for a single password (k-anonymity, HIBP API)
# --------------------------------------------------------------------------

def check_password_pwned(password: str) -> Optional[int]:
    """
    Returns the number of times this password has appeared in known
    breaches, or None if the lookup failed (e.g. no network access).

    Uses the k-anonymity model: only the first 5 characters of the
    SHA-1 hash are sent to the API. The full password, and even the
    full hash, never leave this machine.
    """
    sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]

    try:
        req = urllib.request.Request(
            HIBP_RANGE_URL.format(prefix=prefix),
            headers={"User-Agent": "CredGuard-Auditor/1.0"},
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            body = resp.read().decode("utf-8")
    except (urllib.error.URLError, TimeoutError) as exc:
        print(f"  [!] Could not reach HaveIBeenPwned API: {exc}", file=sys.stderr)
        return None

    for line in body.splitlines():
        candidate_suffix, count = line.split(":")
        if candidate_suffix == suffix:
            return int(count)
    return 0


def cmd_check_password(_args: argparse.Namespace) -> None:
    print("CredGuard - Password Exposure Check")
    print("This checks a password's hash prefix against known breaches.")
    print("The password itself is never sent or stored.\n")
    pw = getpass.getpass("Enter password to check (input hidden): ")
    if not pw:
        print("No password entered.")
        return

    count = check_password_pwned(pw)
    if count is None:
        print("Could not complete the check (network error).")
    elif count == 0:
        print("Not found in known breach corpora. Still verify it isn't reused elsewhere.")
    else:
        print(f"EXPOSED: this password has appeared in {count:,} known breaches.")
        print("Treat it as compromised - rotate it and enable MFA on any account using it.")


# --------------------------------------------------------------------------
# 2. Account roster audit (MFA + staleness + known exposure)
# --------------------------------------------------------------------------

@dataclass
class Account:
    username: str
    email: str
    mfa_enabled: bool
    password_age_days: int
    sensitivity: str
    known_exposure: bool
    risk_score: float = field(default=0.0, init=False)
    reasons: list = field(default_factory=list, init=False)

    def score(self, rotation_days: int) -> None:
        s = 0.0
        reasons = []

        if not self.mfa_enabled:
            s += WEIGHT_NO_MFA
            reasons.append("No MFA enabled")

        if self.known_exposure:
            s += WEIGHT_KNOWN_EXPOSURE
            reasons.append("Credentials found in known breach/infostealer data")

        if self.password_age_days > rotation_days:
            s += WEIGHT_STALE_CREDENTIAL
            reasons.append(f"Password not rotated in {self.password_age_days} days")

        multiplier = SENSITIVITY_MULTIPLIER.get(self.sensitivity.lower(), 1.0)
        self.risk_score = round(s * multiplier, 1)
        self.reasons = reasons if reasons else ["No issues found"]


def _parse_bool(value: str) -> bool:
    return str(value).strip().lower() in ("true", "1", "yes", "y")


def load_accounts(csv_path: str) -> list:
    """
    Expects a CSV with columns:
      username, email, mfa_enabled, password_age_days, sensitivity, known_exposure

    mfa_enabled / known_exposure: true/false
    sensitivity: low / medium / high / critical
    """
    accounts = []
    with open(csv_path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        required = {"username", "email", "mfa_enabled", "password_age_days", "sensitivity"}
        missing = required - set(reader.fieldnames or [])
        if missing:
            raise ValueError(f"CSV is missing required column(s): {', '.join(sorted(missing))}")

        for row in reader:
            accounts.append(Account(
                username=row["username"].strip(),
                email=row["email"].strip(),
                mfa_enabled=_parse_bool(row["mfa_enabled"]),
                password_age_days=int(row["password_age_days"] or 0),
                sensitivity=row["sensitivity"].strip() or "medium",
                known_exposure=_parse_bool(row.get("known_exposure", "false")),
            ))
    return accounts


def audit_accounts(accounts: list, rotation_days: int) -> list:
    for acct in accounts:
        acct.score(rotation_days)
    return sorted(accounts, key=lambda a: a.risk_score, reverse=True)


def render_markdown(accounts: list, rotation_days: int) -> str:
    lines = [
        "# CredGuard Audit Report",
        f"_Generated {datetime.now().strftime('%Y-%m-%d %H:%M')} - rotation policy: {rotation_days} days_",
        "",
        f"Accounts scanned: **{len(accounts)}**",
        f"Accounts with no MFA: **{sum(1 for a in accounts if not a.mfa_enabled)}**",
        f"Accounts with known credential exposure: **{sum(1 for a in accounts if a.known_exposure)}**",
        "",
        "| Risk | Username | Email | Sensitivity | Findings |",
        "|---|---|---|---|---|",
    ]
    for a in accounts:
        lines.append(
            f"| {a.risk_score} | {a.username} | {a.email} | {a.sensitivity} | {'; '.join(a.reasons)} |"
        )
    lines.append("")
    lines.append("## Priority actions")
    top = [a for a in accounts if a.risk_score > 0][:10]
    if not top:
        lines.append("No at-risk accounts found.")
    else:
        for i, a in enumerate(top, 1):
            lines.append(f"{i}. **{a.username}** (risk {a.risk_score}) - {'; '.join(a.reasons)}")
    return "\n".join(lines)


def render_csv(accounts: list) -> str:
    import io
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["risk_score", "username", "email", "sensitivity", "mfa_enabled",
                      "password_age_days", "known_exposure", "findings"])
    for a in accounts:
        writer.writerow([a.risk_score, a.username, a.email, a.sensitivity, a.mfa_enabled,
                          a.password_age_days, a.known_exposure, "; ".join(a.reasons)])
    return buf.getvalue()


def cmd_audit(args: argparse.Namespace) -> None:
    try:
        accounts = load_accounts(args.csv_file)
    except (FileNotFoundError, ValueError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(1)

    ranked = audit_accounts(accounts, args.rotation_days)
    report = render_csv(ranked) if args.format == "csv" else render_markdown(ranked, args.rotation_days)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(report)
        print(f"Report written to {args.output}")
    else:
        print(report)

    at_risk = sum(1 for a in ranked if a.risk_score > 0)
    print(f"\n{at_risk} of {len(ranked)} accounts flagged for review.", file=sys.stderr)


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="credguard",
        description="Credential & MFA exposure auditor, modeled on the Snowflake/UNC5537 breach.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_check = sub.add_parser("check-password", help="Check a single password against known breaches (HIBP k-anonymity).")
    p_check.set_defaults(func=cmd_check_password)

    p_audit = sub.add_parser("audit", help="Audit an account roster CSV for MFA gaps, stale credentials, and known exposure.")
    p_audit.add_argument("csv_file", help="Path to the account roster CSV.")
    p_audit.add_argument("--output", "-o", help="Write the report to this file instead of stdout.")
    p_audit.add_argument("--format", choices=["markdown", "csv"], default="markdown", help="Report format (default: markdown).")
    p_audit.add_argument("--rotation-days", type=int, default=DEFAULT_ROTATION_DAYS,
                          help=f"Flag passwords older than this many days (default: {DEFAULT_ROTATION_DAYS}).")
    p_audit.set_defaults(func=cmd_audit)

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
