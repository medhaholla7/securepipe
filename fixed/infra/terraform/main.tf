# SecurePipe infrastructure on Google Cloud: SECURE VERSION.
# Same services as infra/terraform/, with every INFRA-N misconfiguration fixed.
# The pipeline must pass on this folder with 0 findings.

terraform {
  required_version = ">= 1.5"
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 6.0"
    }
  }
}

provider "google" {
  project = var.project_id
  region  = var.region
}

variable "project_id" {
  type    = string
  default = "securepipe-demo"
}

# London: UK users' personal data stays in the UK (fixes INFRA-1)
variable "region" {
  type    = string
  default = "europe-west2"
}

# ---------------------------------------------------------------------------
# Encryption key we control (CMEK), rotated every 90 days
# ---------------------------------------------------------------------------
resource "google_kms_key_ring" "main" {
  name     = "securepipe-keys"
  location = var.region
}

resource "google_kms_crypto_key" "data" {
  name            = "securepipe-data"
  key_ring        = google_kms_key_ring.main.id
  rotation_period = "7776000s"

  lifecycle {
    prevent_destroy = true
  }
}

# ---------------------------------------------------------------------------
# Storage
# ---------------------------------------------------------------------------
resource "google_storage_bucket" "access_logs" {
  # checkov:skip=CKV_GCP_62: this IS the access-log bucket; logging it to itself would loop
  name                        = "${var.project_id}-access-logs"
  location                    = "EUROPE-WEST2"
  uniform_bucket_level_access = true
  public_access_prevention    = "enforced"

  versioning {
    enabled = true
  }

  encryption {
    default_kms_key_name = google_kms_crypto_key.data.id
  }

  labels = {
    data_classification = "internal"
  }
}

resource "google_storage_bucket" "exports" {
  name                        = "${var.project_id}-notes-exports"
  location                    = "EUROPE-WEST2" # fixes INFRA-1
  uniform_bucket_level_access = true           # fixes INFRA-2
  public_access_prevention    = "enforced"     # fixes INFRA-5: public access blocked at bucket level

  versioning {
    enabled = true # fixes INFRA-3
  }

  logging {
    log_bucket = google_storage_bucket.access_logs.name # fixes INFRA-4
  }

  encryption {
    default_kms_key_name = google_kms_crypto_key.data.id
  }

  labels = {
    data_classification = "personal"
  }
}
# fixes INFRA-5: no allUsers / allAuthenticatedUsers IAM binding

# ---------------------------------------------------------------------------
# Network and admin VM
# ---------------------------------------------------------------------------
resource "google_compute_network" "vpc" {
  name                    = "securepipe-vpc"
  auto_create_subnetworks = false
}

resource "google_compute_subnetwork" "app" {
  name                     = "securepipe-app"
  ip_cidr_range            = "10.10.0.0/24"
  region                   = var.region
  network                  = google_compute_network.vpc.id
  private_ip_google_access = true

  log_config { # fixes INFRA-6
    aggregation_interval = "INTERVAL_5_SEC"
    flow_sampling        = 0.5
    metadata             = "INCLUDE_ALL_METADATA"
  }
}

# fixes INFRA-7: SSH only through Google's Identity-Aware Proxy range, no RDP
resource "google_compute_firewall" "admin" {
  name    = "allow-ssh-from-iap"
  network = google_compute_network.vpc.name

  allow {
    protocol = "tcp"
    ports    = ["22"]
  }
  source_ranges = ["35.235.240.0/20"]
}

resource "google_service_account" "admin_vm" {
  account_id   = "securepipe-admin-vm"
  display_name = "Least-privilege identity for the admin VM"
}

resource "google_compute_instance" "admin" {
  # checkov:skip=CKV_GCP_38: CSEK means sending a raw key with every API call; the disk uses a Cloud KMS key (CMEK) instead
  name         = "securepipe-admin"
  machine_type = "e2-micro"
  zone         = "${var.region}-a"

  boot_disk {
    initialize_params {
      image = "debian-cloud/debian-12"
    }
    kms_key_self_link = google_kms_crypto_key.data.id
  }

  network_interface {
    subnetwork = google_compute_subnetwork.app.id
    # fixes INFRA-8: no access_config, so no public IP
  }

  metadata = {
    serial-port-enable     = "false" # fixes INFRA-9
    block-project-ssh-keys = "true"  # fixes INFRA-10
    enable-oslogin         = "true"  # logins tied to Google identities
  }

  service_account { # fixes INFRA-11
    email  = google_service_account.admin_vm.email
    scopes = ["logging-write", "monitoring-write"]
  }

  shielded_instance_config { # fixes INFRA-12
    enable_secure_boot          = true
    enable_vtpm                 = true
    enable_integrity_monitoring = true
  }
}

# ---------------------------------------------------------------------------
# Database
# ---------------------------------------------------------------------------
resource "google_sql_database_instance" "notes" {
  # checkov:skip=CKV_GCP_6: false positive, the check only reads the deprecated require_ssl; ssl_mode = ENCRYPTED_ONLY below enforces SSL
  name                = "securepipe-notes-db"
  database_version    = "POSTGRES_18"
  region              = var.region
  deletion_protection = true # fixes INFRA-13

  settings {
    tier = "db-f1-micro"
    user_labels = {
      data_classification = "personal"
    }

    backup_configuration { # fixes INFRA-14
      enabled                        = true
      point_in_time_recovery_enabled = true
    }

    # Trivy GCP-0015 is the same false positive as CKV_GCP_6 (reads require_ssl only)
    #trivy:ignore:GCP-0015
    ip_configuration {
      ipv4_enabled    = false # fixes INFRA-16: private IP only
      private_network = google_compute_network.vpc.id
      ssl_mode        = "ENCRYPTED_ONLY" # fixes INFRA-15
    }

    # Audit-relevant logging on the database
    database_flags {
      name  = "log_connections"
      value = "on"
    }
    database_flags {
      name  = "log_disconnections"
      value = "on"
    }
    database_flags {
      name  = "log_checkpoints"
      value = "on"
    }
    database_flags {
      name  = "log_lock_waits"
      value = "on"
    }
    database_flags {
      name  = "log_hostname"
      value = "on"
    }
    database_flags {
      name  = "log_duration"
      value = "on"
    }
    database_flags {
      name  = "log_temp_files"
      value = "0"
    }
    database_flags {
      name  = "log_min_messages"
      value = "error"
    }
    database_flags {
      name  = "log_min_error_statement"
      value = "error"
    }
    database_flags {
      name  = "cloudsql.enable_pgaudit"
      value = "on"
    }
    # Log schema changes (DDL), not every query: logging all statements would
    # copy users' personal data into the logs (the same GDPR issue as flaw 10).
    database_flags {
      name  = "log_statement"
      value = "ddl"
    }
  }
}

# ---------------------------------------------------------------------------
# Cloud Run
# ---------------------------------------------------------------------------
resource "google_secret_manager_secret" "jwt" {
  secret_id = "notes-jwt-secret"
  replication {
    user_managed {
      replicas {
        location = "europe-west2"
      }
    }
  }
}

resource "google_cloud_run_v2_service" "api" {
  name     = "securepipe-notes-api"
  location = var.region

  template {
    containers {
      image = "europe-docker.pkg.dev/securepipe-demo/app/notes@sha256:0000000000000000000000000000000000000000000000000000000000000000"
      env {
        name = "JWT_SECRET" # fixes INFRA-17: read from Secret Manager at runtime
        value_source {
          secret_key_ref {
            secret  = google_secret_manager_secret.jwt.secret_id
            version = "latest"
          }
        }
      }
    }
  }
}
