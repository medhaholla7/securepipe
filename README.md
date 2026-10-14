# SecurePipe: break it, then make it unbreakable

A small web app I deliberately built with security flaws, and a CI/CD pipeline
that catches each flaw automatically before it can be merged. The point is to
show the full loop a security engineer runs: **attack, defend, automate.**

> The app is intentionally vulnerable. It is for security testing only and
> must not be deployed to the public internet. The planted flaws are listed in
> [VULNERABILITIES.md](VULNERABILITIES.md).

## Parts

1. **Attack** - a FastAPI "notes" API seeded with 9 classic flaws (IDOR, SQL
   injection, a hardcoded secret, a committed `.env`, an outdated dependency,
   a root container, and more).
2. **Defend and automate** (in progress) - a GitHub Actions pipeline that blocks
   a pull request if it reintroduces any of these, using:
   - **Gitleaks** - committed secrets
   - **Semgrep** - insecure code patterns (SQLi, CORS, plaintext passwords)
   - **Trivy** - vulnerable dependencies and container issues
   - **Checkov** - infrastructure-as-code misconfigurations
3. **Privacy** (planned) - a check that flags personal data (email, phone) in
   logs and maps each control to the relevant GDPR article.

## Run it locally

```bash
docker compose up --build
# or without Docker:
pip install -r app/requirements.txt && uvicorn main:app --app-dir app
```

## Results

Filled in as the pipeline is built: how many of the 9 seeded flaws the pipeline
catches, how long it adds to a build, and false positives on clean code.

## Why this project

It maps to the five things a security engineer does day to day: find
weaknesses, attack and defend, automate controls into the pipeline, protect
personal data, and track new vulnerabilities.

### Results so far

- Custom Semgrep rules: **7 findings across 5 of the 9 seeded flaws** (SQL injection, hardcoded secret, CORS wildcard, plaintext passwords, debug endpoint leaking config).
- False positives on a clean, fixed version of the same code: **0**.
- Gitleaks, Trivy and Checkov run in GitHub Actions on every push (results added after the first run).
