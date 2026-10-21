# Seeded vulnerabilities

This app is **deliberately insecure**. Each flaw below is planted so the CI/CD
security pipeline can be shown catching it. "Caught by" is taken from real
GitHub Actions runs on this repo.

| # | Flaw | Where | CWE / OWASP | Caught by |
|---|------|-------|-------------|-----------|
| 1 | Hardcoded signing secret | `app/main.py` `JWT_SECRET` | CWE-798 | Semgrep (custom + p/python), Gitleaks (custom rule) |
| 2 | CORS allows any origin with credentials | `app/main.py` middleware | CWE-942 | Semgrep (custom + p/python) |
| 3 | Passwords stored in plain text | `app/main.py` `init_db` | CWE-256 | Semgrep (custom) |
| 4 | SQL injection in login | `app/main.py` `/login` | CWE-89, OWASP A03 | Semgrep (custom) |
| 5 | IDOR / broken object level auth | `app/main.py` `/notes/{id}` | CWE-639, OWASP API1 | Access-control test (`tests/`) |
| 6 | Debug endpoint leaks config and secret | `app/main.py` `/debug` | CWE-215 | Semgrep (custom) |
| 7 | Outdated dependency (PyJWT 1.7.1) | `app/requirements.txt` | CWE-1395 | Trivy (5 CVEs: 1 critical, 4 high) |
| 8 | Secrets committed to repo (`.env`) | `.env` | CWE-798 | Gitleaks (custom rule) |
| 9 | Container runs as root | `app/Dockerfile` | CWE-250 | Trivy (DS-0002), Checkov (CKV_DOCKER_3) |
| 10 | Passwords and personal data written to logs | `app/main.py` `/login`, `/signup` | CWE-532, GDPR Art. 5(1)(c), 32 | Semgrep (custom), PII log scan (`ci/pii_scan.py`) |
| 11 | Any user can read everyone's email and phone | `app/main.py` `/users` | CWE-359, GDPR Art. 5(1)(c) | Privacy test (`tests/`) |

The fixed version of the code is in `fixed/main.py`.

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

## Part 4: cloud and Kubernetes infrastructure

The same app, described as infrastructure code: Google Cloud in Terraform
(`infra/terraform/`) and Kubernetes manifests (`infra/k8s/`). 27 more planted
misconfigurations. "Default" means Checkov's and Trivy's built-in rules;
"custom" means the 4 rules in `.checkov/`.

| # | Misconfiguration | Where | Caught by |
|---|------------------|-------|-----------|
| INFRA-1 | UK users' personal data stored in a US region | bucket and Cloud SQL `location`/`region` | **Custom only** (CKV_SP_1, UK GDPR Art. 44) |
| INFRA-2 | Per-object ACLs allowed on the bucket | `uniform_bucket_level_access` | Checkov CKV_GCP_29, Trivy GCP-0002 |
| INFRA-3 | No bucket versioning | `google_storage_bucket.exports` | Checkov CKV_GCP_78, Trivy GCP-0078 |
| INFRA-4 | No bucket access logging | `google_storage_bucket.exports` | Checkov CKV_GCP_62, Trivy GCP-0077 |
| INFRA-5 | Bucket readable by anyone on the internet | `allUsers` IAM binding | Checkov CKV_GCP_28 / CKV_GCP_114, Trivy GCP-0001 |
| INFRA-6 | VPC flow logs off | `google_compute_subnetwork.app` | Checkov CKV_GCP_26, Trivy GCP-0029 / GCP-0076 |
| INFRA-7 | SSH and RDP open to 0.0.0.0/0 | `google_compute_firewall.admin` | Checkov CKV_GCP_2 / CKV_GCP_3, Trivy GCP-0027 / 0070 / 0071 |
| INFRA-8 | Public IP on the admin VM | `access_config {}` | Checkov CKV_GCP_40, Trivy GCP-0031 |
| INFRA-9 | Serial console enabled | VM `metadata` | Checkov CKV_GCP_35, Trivy GCP-0032 |
| INFRA-10 | Project-wide SSH keys accepted | VM `metadata` | Checkov CKV_GCP_32, Trivy GCP-0030 |
| INFRA-11 | Default service account with full `cloud-platform` scope | VM `service_account` | Checkov CKV_GCP_30 / CKV_GCP_31, Trivy GCP-0044 |
| INFRA-12 | Shielded VM off | `google_compute_instance.admin` | Checkov CKV_GCP_39, Trivy GCP-0041 / 0045 / 0067 |
| INFRA-13 | Database deletion protection off | `deletion_protection = false` | **Custom only** (CKV_SP_2) |
| INFRA-14 | Database backups off | `backup_configuration` | Checkov CKV_GCP_14, Trivy GCP-0024 |
| INFRA-15 | Plain-text database connections allowed | `ssl_mode` | Checkov CKV_GCP_6, Trivy GCP-0015 |
| INFRA-16 | Database reachable from the whole internet | `authorized_networks 0.0.0.0/0` | Checkov CKV_GCP_11 / CKV_GCP_60, Trivy GCP-0017 |
| INFRA-17 | JWT secret as a plain-text Cloud Run env value | `google_cloud_run_v2_service.api` | **Custom only** (CKV_SP_3) |
| K8S-1 | Runs in the `default` namespace | `metadata.namespace` | Checkov CKV_K8S_21, Trivy KSV-0110 |
| K8S-2 | Pod shares the node's network | `hostNetwork: true` | Checkov CKV_K8S_19, Trivy KSV-0009 |
| K8S-3 | Mutable `latest` image tag, no digest | `image` | Checkov CKV_K8S_14 / CKV_K8S_43, Trivy KSV-0013 |
| K8S-4 | JWT secret as a plain-text env value | `env` | **Custom only** (CKV_SP_4) |
| K8S-5 | Privileged container | `securityContext.privileged` | Checkov CKV_K8S_16, Trivy KSV-0017 |
| K8S-6 | Runs as root | `runAsUser: 0` | Checkov CKV_K8S_23, Trivy KSV-0012 / KSV-0105 |
| K8S-7 | Privilege escalation allowed | `allowPrivilegeEscalation` | Checkov CKV_K8S_20, Trivy KSV-0001 |
| K8S-8 | SYS_ADMIN and NET_ADMIN capabilities added | `capabilities.add` | Checkov CKV_K8S_25 / CKV_K8S_39, Trivy KSV-0005 / KSV-0022 |
| K8S-9 | No CPU or memory limits | `resources` | Checkov CKV_K8S_10 to 13, Trivy KSV-0011 / 0015 / 0016 / 0018 |
| K8S-10 | No liveness or readiness probes | container spec | Checkov CKV_K8S_8 / CKV_K8S_9 (Trivy has no rule) |

The secure versions are in `fixed/infra/`. Checkov (default + custom rules) and
Trivy both report **0 findings** there. Four checks are suppressed in the fixed
code, each with the reason written next to it:

| Suppressed | Why |
|------------|-----|
| CKV_GCP_6 and Trivy GCP-0015 (SSL not enforced on Cloud SQL) | False positive: both read the deprecated `require_ssl` setting; the fixed code uses its replacement, `ssl_mode = "ENCRYPTED_ONLY"` |
| CKV_GCP_38 (disk not encrypted with CSEK) | CSEK means sending a raw key with every API call; the disk uses a Cloud KMS key (CMEK) instead |
| CKV_GCP_62 on the access-log bucket | It is the log bucket; logging it into itself would loop |
