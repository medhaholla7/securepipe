"""
Turn scanner JSON output into GitHub annotations and a pass/fail exit code.

Each finding is printed as a ::error:: workflow command, so it shows inline on
the pull request diff and on the run page, instead of being buried in logs.

usage: python ci/annotate.py {semgrep|trivy|gitleaks|checkov} report.json [path-prefix]
"""
import json
import os
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


def _real_path(path):
    # Checkov's Kubernetes runner repeats the scanned folder in its paths
    # (infra/infra/k8s/...); collapse it so the annotation lands on the real file.
    parts = path.split("/")
    if not os.path.exists(path) and len(parts) > 1 and parts[0] == parts[1]:
        path = "/".join(parts[1:])
    return path


def checkov(d):
    for run in d if isinstance(d, list) else [d]:
        for f in run.get("results", {}).get("failed_checks", []):
            path = os.path.relpath(f["file_abs_path"]) if f.get("file_abs_path") else f["file_path"].lstrip("/")
            yield _real_path(path), f["file_line_range"][0], (
                f"[{f['check_id']}] {f['check_name']} ({f['resource']})")


def main():
    tool, path = sys.argv[1], sys.argv[2]
    prefix = sys.argv[3] if len(sys.argv) > 3 else ""  # when a scanner reports paths relative to a subfolder
    with open(path) as fh:
        data = json.load(fh)
    findings = list({"semgrep": semgrep, "trivy": trivy, "gitleaks": gitleaks,
                     "checkov": checkov}[tool](data))
    for file, line, msg in findings:
        print(f"::error file={esc(prefix + file)},line={line},title={tool}::{esc(msg)}")
    print(f"{tool}: {len(findings)} finding(s)")
    sys.exit(1 if findings else 0)


if __name__ == "__main__":
    main()
