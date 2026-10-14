# SecurePipe: break it, then make it unbreakable

![security-pipeline](https://github.com/medhaholla7/securepipe/actions/workflows/security.yml/badge.svg)

A small web app I deliberately built with security flaws, and a CI/CD pipeline
that catches each flaw automatically before it can be merged. It shows the full
loop a security engineer runs: **find the weakness, prove it, automate the control.**

> The app is intentionally vulnerable. It is for security testing only and
> must not be deployed to the public internet. The planted flaws are listed in
> [VULNERABILITIES.md](VULNERABILITIES.md). The badge is red on purpose: the
> pipeline is doing its job by failing on the vulnerable code.

## What's in the repo

| Path | What it is |
|------|------------|
| `app/` | FastAPI "notes" API with 9 planted flaws (SQLi, IDOR, hardcoded secret, old PyJWT, root container...) |
| `fixed/` | The same app with every code flaw fixed, used to prove the rules don't raise false positives |
| `.github/workflows/security.yml` | The pipeline: 6 jobs, runs on every push and pull request |
| `.semgrep/rules.yaml` | 5 custom Semgrep rules, each tagged with a CWE and a fix message |
| `.gitleaks.toml` | 2 custom Gitleaks rules on top of the default set |
| `tests/` | Access-control test that catches the IDOR |
| `ci/annotate.py` | Turns scanner JSON into inline GitHub annotations |

## The pipeline

| Job | Tool | Catches |
|-----|------|---------|
| Secrets | Gitleaks (full git history) | Committed keys and passwords |
| SAST | Semgrep (custom rules + `p/python`) | SQLi, hardcoded secrets, CORS, plaintext passwords, debug leaks |
| False-positive check | Semgrep on `fixed/` | Must find nothing |
| Access control | pytest | IDOR: user B reading user A's note |
| Dependencies and container | Trivy | Known CVEs, root container |
| Infrastructure as code | Checkov | Dockerfile misconfigurations |

## Results (from real GitHub Actions runs)

- **All 9 planted flaws caught.** 8 by scanners, plus the IDOR by the
  access-control test.
- **0 false positives** from the custom Semgrep rules on the fixed code.
- Trivy found **5 known CVEs** in PyJWT 1.7.1 (1 critical, 4 high), including
  authentication bypass via forged tokens.

## What I found while building it

- **Default Gitleaks rules missed every planted secret.** They only recognise
  real provider key formats, not a hand-written JWT key or a password in `.env`.
  I wrote 2 custom rules, which caught all 3.
- **The Gitleaks Action only scanned the commits in each push**, so a secret
  added in an earlier commit was never checked. I switched to scanning the full
  history every run.
- **My first "hardcoded secret" Semgrep rule fired on the SQL line**
  (`password='{body.password}'`), which is a placeholder, not a secret. I
  tightened the regex so each finding is labelled correctly.
- **The pinned Trivy Action version no longer existed upstream**, which broke
  the job at setup. I replaced it with a pinned release binary.
- **Scanners can't see logic flaws.** The IDOR code looks fine; it just never
  checks who owns the note. Only a test that acts like an attacker catches it.

## Run it locally

```bash
docker compose up --build
# or without Docker:
pip install -r app/requirements.txt && uvicorn main:app --app-dir app
pytest -q tests/   # fails: proves the IDOR is there
```

## Next

A privacy check that flags personal data (emails, phone numbers) written to
logs, mapped to the relevant GDPR articles.
