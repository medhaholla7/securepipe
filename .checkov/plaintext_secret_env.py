"""CKV_SP_3 / CKV_SP_4: no secrets as plain-text environment variables.

A JWT key written straight into Cloud Run or Kubernetes config ends up in git,
in deploy logs and in anyone's `kubectl describe`. Default Checkov rules miss
it: CKV_K8S_35 only flags secretKeyRef (the safer pattern), not a literal value.
"""
import re

from checkov.common.models.enums import CheckCategories, CheckResult
from checkov.kubernetes.checks.resource.base_container_check import BaseK8sContainerCheck
from checkov.terraform.checks.resource.base_resource_check import BaseResourceCheck

SECRET_NAME = re.compile(r"(SECRET|PASSWORD|PASSWD|TOKEN|API_KEY|PRIVATE_KEY|SIGNING_KEY)", re.I)


def _first(v):
    return v[0] if isinstance(v, list) and v else v


class CloudRunPlaintextSecret(BaseResourceCheck):
    def __init__(self):
        super().__init__(
            name="Cloud Run must read secrets from Secret Manager, not plain-text env values",
            id="CKV_SP_3",
            categories=[CheckCategories.SECRETS],
            supported_resources=["google_cloud_run_v2_service", "google_cloud_run_service"],
        )

    def scan_resource_conf(self, conf):
        template = _first(conf.get("template")) or {}
        spec = _first(template.get("spec")) or template  # v1 nests containers under spec
        for container in spec.get("containers") or []:
            container = _first(container) or {}
            for env in container.get("env") or []:
                env = _first(env) or {}
                name = str(_first(env.get("name")) or "")
                if SECRET_NAME.search(name) and env.get("value") is not None:
                    return CheckResult.FAILED
        return CheckResult.PASSED


class K8sPlaintextSecret(BaseK8sContainerCheck):
    def __init__(self):
        super().__init__(
            name="Containers must not set secrets as plain-text env values",
            id="CKV_SP_4",
        )

    def scan_container_conf(self, metadata, conf):
        self.evaluated_container_keys = ["env"]
        for env in conf.get("env") or []:
            if isinstance(env, dict) and SECRET_NAME.search(str(env.get("name", ""))) and "value" in env:
                if not str(env.get("name", "")).upper().endswith("_FILE"):
                    return CheckResult.FAILED
        return CheckResult.PASSED


cloud_run_check = CloudRunPlaintextSecret()
k8s_check = K8sPlaintextSecret()
