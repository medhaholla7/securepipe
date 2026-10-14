"""
Scan runtime log files for personal data and credentials.

Static rules (Semgrep) catch PII written to logs in code you can see. This
catches what actually lands in the log when the app runs, including PII that
reaches a log through a path no rule anticipated.

Each finding is printed as a GitHub annotation with the CWE and the GDPR
article it puts at risk. Matched values are masked in the output, so the scan
itself never re-leaks the data.

usage: python ci/pii_scan.py app.log [more.log ...]
"""
import re
import sys

GDPR_LOGS = "GDPR Art. 5(1)(c) data minimisation, Art. 32 security of processing"

CHECKS = [
    ("email", re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"), "CWE-532", GDPR_LOGS),
    ("phone", re.compile(r"\+\d{1,3}[\s-]?\d{2,4}[\s-]?\d{3,4}[\s-]?\d{3,4}"), "CWE-532", GDPR_LOGS),
    ("password", re.compile(r"(?i)\b(password|passwd|pwd)=\S+"), "CWE-532", "GDPR Art. 32 security of processing"),
    ("jwt", re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"), "CWE-532", "GDPR Art. 32 security of processing"),
    ("card", re.compile(r"\b(?:\d[ -]?){13,19}\b"), "CWE-359", "GDPR Art. 32; PCI DSS 3.4"),
]


def luhn(digits: str) -> bool:
    d = [int(c) for c in digits if c.isdigit()]
    s = sum(d[-1::-2]) + sum(sum(divmod(2 * x, 10)) for x in d[-2::-2])
    return 13 <= len(d) <= 19 and s % 10 == 0


def mask(v: str) -> str:
    return v[:2] + "***" + v[-2:] if len(v) > 6 else "***"


def scan(path):
    with open(path, errors="replace") as fh:
        for n, line in enumerate(fh, 1):
            for kind, rx, cwe, gdpr in CHECKS:
                for m in rx.finditer(line):
                    if kind == "email" and "***@" in m.group(0):
                        continue  # already masked by the app
                    if kind == "card" and not luhn(m.group(0)):
                        continue
                    yield path, n, kind, mask(m.group(0)), cwe, gdpr


def main():
    findings = [f for p in sys.argv[1:] for f in scan(p)]
    for path, n, kind, val, cwe, gdpr in findings:
        print(f"::error file={path},line={n},title=pii-scan::[{kind}] {cwe} '{val}' in log. Puts {gdpr} at risk.")
    print(f"pii-scan: {len(findings)} finding(s)")
    sys.exit(1 if findings else 0)


if __name__ == "__main__":
    main()
