"""
Turn scanner JSON output into GitHub annotations and a pass/fail exit code.

Each finding is printed as a ::error:: workflow command, so it shows inline on
the pull request diff and on the run page, instead of being buried in logs.

usage: python ci/annotate.py {semgrep|trivy|gitleaks} report.json
"""
import json
import sys


def esc(s: str) -> str:
    return str(s).replace("%", "%25").replace("\r", "").replace("\n", " ")


def semgrep(d):
    for r in d.get("results", []):
        rule = r["check_id"].split(".")[-1]
        cwe = r["extra"].get("metadata", {}).get("cwe", "")
        cwe = cwe[0] if isinstance(cwe, list) else cwe
        yield r["path"], r["start"]["line"], f"[{rule}] {cwe} {r['extra']['message']}"


def trivy(d):
    for res in d.get("Results", []) or []:
        tgt = res.get("Target", "")
        for v in res.get("Vulnerabilities") or []:
            yield tgt, 1, (f"[{v['VulnerabilityID']}] {v['Severity']} {v['PkgName']} "
                           f"{v['InstalledVersion']} -> fix {v.get('FixedVersion', '?')}: "
                           f"{v.get('Title', '')}")
        for m in res.get("Misconfigurations") or []:
            line = (m.get("CauseMetadata") or {}).get("StartLine") or 1
            yield tgt, line, f"[{m['ID']}] {m['Severity']} {m['Title']}"


def gitleaks(d):
    for f in d or []:
        yield f["File"], f["StartLine"], (f"[{f['RuleID']}] {f['Description']} "
                                          f"(commit {f.get('Commit', '')[:7]})")


def main():
    tool, path = sys.argv[1], sys.argv[2]
    with open(path) as fh:
        data = json.load(fh)
    findings = list({"semgrep": semgrep, "trivy": trivy, "gitleaks": gitleaks}[tool](data))
    for file, line, msg in findings:
        print(f"::error file={esc(file)},line={line},title={tool}::{esc(msg)}")
    print(f"{tool}: {len(findings)} finding(s)")
    sys.exit(1 if findings else 0)


if __name__ == "__main__":
    main()
