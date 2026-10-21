# SecurePipe infrastructure on Google Cloud: DELIBERATELY INSECURE.
# Each planted misconfiguration is tagged INFRA-N and listed in VULNERABILITIES.md.
# The pipeline must fail on this folder. The secure version is in fixed/infra/terraform/.
# Never apply this to a real project.

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

variable "region" {
  type    = string
  default = "us-central1"
}

# ---------------------------------------------------------------------------
# Storage: nightly exports of the notes database (contains users' personal data)
# ---------------------------------------------------------------------------
resource "google_storage_bucket" "exports" {
  name     = "${var.project_id}-notes-exports"
  location = "US" # INFRA-1: UK users' personal data stored outside the UK/EU

  uniform_bucket_level_access = false # INFRA-2: per-object ACLs allowed
  force_destroy               = true

  labels = {
    data_classification = "personal"
  }
  # INFRA-3: no versioning, so deleted or overwritten exports cannot be recovered
  # INFRA-4: no access logging on the bucket
}

# INFRA-5: anyone on the internet can read every export
resource "google_storage_bucket_iam_member" "public_read" {
  bucket = google_storage_bucket.exports.name
  role   = "roles/storage.objectViewer"
  member = "allUsers"
}

# ---------------------------------------------------------------------------
# Network and admin VM
# ---------------------------------------------------------------------------
resource "google_compute_network" "vpc" {
  name                    = "securepipe-vpc"
  auto_create_subnetworks = false
}

resource "google_compute_subnetwork" "app" {
  name          = "securepipe-app"
  ip_cidr_range = "10.10.0.0/24"
  region        = var.region
  network       = google_compute_network.vpc.id
  # INFRA-6: VPC flow logs off, so there is no record of network traffic
}

# INFRA-7: SSH and RDP open to the whole internet
resource "google_compute_firewall" "admin" {
  name    = "allow-admin-from-anywhere"
  network = google_compute_network.vpc.name

  allow {
    protocol = "tcp"
    ports    = ["22", "3389"]
  }
  source_ranges = ["0.0.0.0/0"]
}

resource "google_compute_instance" "admin" {
  name         = "securepipe-admin"
  machine_type = "e2-micro"
  zone         = "${var.region}-a"

  boot_disk {
    initialize_params {
      image = "debian-cloud/debian-12"
    }
  }

  network_interface {
    subnetwork = google_compute_subnetwork.app.id
    access_config {} # INFRA-8: public IP on an admin box
  }

  metadata = {
    serial-port-enable     = "true"  # INFRA-9: interactive serial console enabled
    block-project-ssh-keys = "false" # INFRA-10: any project-wide SSH key can log in
  }

  # INFRA-11: default compute service account with full cloud-platform scope
  service_account {
    scopes = ["cloud-platform"]
  }
  # INFRA-12: no Shielded VM (secure boot / integrity monitoring off)
}

# ---------------------------------------------------------------------------
# Database for the notes API
# ---------------------------------------------------------------------------
resource "google_sql_database_instance" "notes" {
  name                = "securepipe-notes-db"
  database_version    = "POSTGRES_15"
  region              = var.region
  deletion_protection = false # INFRA-13: one command can delete the database

  settings {
    tier = "db-f1-micro"
    user_labels = {
      data_classification = "personal"
    }

    backup_configuration {
      enabled = false # INFRA-14: no backups
    }

    ip_configuration {
      ipv4_enabled = true
      ssl_mode     = "ALLOW_UNENCRYPTED_AND_ENCRYPTED" # INFRA-15: plaintext connections allowed
      authorized_networks {
        name  = "anywhere"
        value = "0.0.0.0/0" # INFRA-16: database reachable from the whole internet
      }
    }
  }
}

# ---------------------------------------------------------------------------
# Cloud Run service running the notes API container
# ---------------------------------------------------------------------------
resource "google_cloud_run_v2_service" "api" {
  name     = "securepipe-notes-api"
  location = var.region

  template {
    containers {
      image = "europe-docker.pkg.dev/securepipe-demo/app/notes:latest"
      env {
        name  = "JWT_SECRET"
        value = "dev-secret-change-me-8f2a91" # INFRA-17: secret in plain text in the config
      }
    }
  }
}
