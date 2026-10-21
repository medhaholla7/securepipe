"""CKV_SP_1: personal data must stay in the UK or EU (UK GDPR Art. 44, international transfers).

Neither Checkov nor Trivy has a default rule for where data is stored, so a
bucket full of UK users' personal data in a US region passes both scanners.
"""
from checkov.common.models.enums import CheckCategories, CheckResult
from checkov.terraform.checks.resource.base_resource_check import BaseResourceCheck

ALLOWED_PREFIXES = ("EUROPE-", "EU")


def _first(v):
    return v[0] if isinstance(v, list) and v else v


class UkDataResidency(BaseResourceCheck):
    def __init__(self):
        super().__init__(
            name="Personal data must be stored in a UK or EU location (UK GDPR Art. 44)",
            id="CKV_SP_1",
            categories=[CheckCategories.GENERAL_SECURITY],
            supported_resources=["google_storage_bucket", "google_sql_database_instance"],
        )

    def scan_resource_conf(self, conf):
        if self.entity_type == "google_storage_bucket":
            labels = _first(conf.get("labels")) or {}
            location = str(_first(conf.get("location")) or "")
        else:
            settings = _first(conf.get("settings")) or {}
            labels = _first(settings.get("user_labels")) or {}
            location = str(_first(conf.get("region")) or "")
        if labels.get("data_classification") != "personal":
            return CheckResult.PASSED
        if location.upper().startswith(ALLOWED_PREFIXES):
            return CheckResult.PASSED
        return CheckResult.FAILED


check = UkDataResidency()
