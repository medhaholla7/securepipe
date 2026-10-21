"""CKV_SP_2: the production database must have deletion protection on.

With deletion_protection = false, one terraform destroy (or a typo in a plan)
deletes the database. Default Checkov and Trivy rules do not check this.
"""
from checkov.common.models.enums import CheckCategories, CheckResult
from checkov.terraform.checks.resource.base_resource_check import BaseResourceCheck


class SqlDeletionProtection(BaseResourceCheck):
    def __init__(self):
        super().__init__(
            name="Cloud SQL instances must keep deletion protection on",
            id="CKV_SP_2",
            categories=[CheckCategories.BACKUP_AND_RECOVERY],
            supported_resources=["google_sql_database_instance"],
        )

    def scan_resource_conf(self, conf):
        value = conf.get("deletion_protection", [True])
        value = value[0] if isinstance(value, list) else value
        return CheckResult.FAILED if value in (False, "false") else CheckResult.PASSED


check = SqlDeletionProtection()
