# Seeded vulnerabilities

This app is **deliberately insecure**. Each flaw below is planted so the CI/CD
security pipeline can be shown catching it. The "Caught by" column is filled in
as each scanner is added in Part 2.

| # | Flaw | Where | CWE / OWASP | Caught by |
|---|------|-------|-------------|-----------|
| 1 | Hardcoded signing secret | `app/main.py` `JWT_SECRET` | CWE-798 | Gitleaks / Semgrep |
| 2 | CORS allows any origin with credentials | `app/main.py` middleware | CWE-942 | Semgrep |
| 3 | Passwords stored in plain text | `app/main.py` `init_db` | CWE-256 | Semgrep |
| 4 | SQL injection in login | `app/main.py` `/login` | CWE-89, OWASP A03 | Semgrep |
| 5 | IDOR / broken object level auth | `app/main.py` `/notes/{id}` | CWE-639, OWASP API1 | custom check / manual |
| 6 | Debug endpoint leaks config and secret | `app/main.py` `/debug` | CWE-215 | Semgrep / manual |
| 7 | Outdated dependency (PyJWT 1.7.1) | `app/requirements.txt` | CWE-1395 | Trivy |
| 8 | Secret committed to repo (`.env`) | `.env` | CWE-798 | Gitleaks |
| 9 | Container runs as root | `app/Dockerfile` | CWE-250 | Trivy / Checkov |

## Proof the flaws are real (local)

```bash
pip install -r app/requirements.txt
uvicorn main:app --app-dir app
# IDOR: log in as bob, then read alice's note
TOKEN=$(curl -s localhost:8000/login -H 'content-type: application/json' \
  -d '{"username":"bob","password":"bobpw"}' | jq -r .token)
curl -s localhost:8000/notes/1 -H "authorization: Bearer $TOKEN"   # returns alice's note
# SQL injection: log in with no real password
curl -s localhost:8000/login -H 'content-type: application/json' \
  -d '{"username":"x'"'"' OR '"'"'1'"'"'='"'"'1'"'"' --","password":"x"}'
```
