# -------------------------------------------------------------------
# SERVICE ACCOUNT: Dedicated identity for GKE nodes
# -------------------------------------------------------------------
resource "google_service_account" "default" {
  account_id   = "gke-node-service-account"
  display_name = "GKE node service account"
}

data "google_project" "project" {
}

resource "google_project_iam_member" "default" {
  project = data.google_project.project.project_id
  # <-- BEST PRACTICE: Use the minimal privilege nodeServiceAccount role
  role    = "roles/container.nodeServiceAccount"
  member  = "serviceAccount:${google_service_account.default.email}"
}

# -------------------------------------------------------------------
# NETWORK: Custom VPC with IPv6 enabled
# -------------------------------------------------------------------
resource "google_compute_network" "default" {
  name = "gcp-network"

  # BEST PRACTICE: Custom mode VPC gives you full control
  auto_create_subnetworks  = false
  enable_ula_internal_ipv6 = true
}

# -------------------------------------------------------------------
# SUBNET: Single subnet for GKE cluster (nodes, pods, services)
# -------------------------------------------------------------------
resource "google_compute_subnetwork" "cluster-subnet" {
  name = "gke-cluster-dev"

  ip_cidr_range = "10.0.0.0/24" # Primary range for nodes
  region        = "europe-west4"
  network       = google_compute_network.default.id
  
  # --- BEST PRACTICE: Enable VPC Flow Logs for security auditing ---
  log_config {
    aggregation_interval = "INTERVAL_10_MIN"
    flow_sampling        = 0.5 # 50% of traffic, adjust as needed
    metadata             = "INCLUDE_ALL_METADATA"
  }

  # --- SECURITY HARDENING ---
  # CRITICAL: This allows your private nodes to reach Google APIs
  # (like Vertex AI and Artifact Registry) over Google's internal network.
  private_ip_google_access = true
  private_ipv6_google_access = true

  # --- GKE CONFIGURATION ---
  stack_type       = "IPV4_IPV6"
  ipv6_access_type = "INTERNAL" # No external IPv6

  # BEST PRACTICE: Sized secondary ranges for Autopilot
  secondary_ip_range {
    range_name    = "services-range"
    ip_cidr_range = "192.168.0.0/24" # /24 is fine for services
  }

  secondary_ip_range {
    range_name    = "pod-ranges"
    # BEST PRACTICE: /20 gives more pod IPs (4,094) than /24.
    # Autopilot can use many IPs, so don't be too restrictive.
    ip_cidr_range = "192.168.1.0/24"
  }
}

# -------------------------------------------------------------------
# GKE CLUSTER: Hardened Private Autopilot Cluster
# -------------------------------------------------------------------
resource "google_container_cluster" "default" {
  name     = "v0-1-cluster"
  location = "europe-west4"

  # --- Autopilot enforces many best practices by default ---
  # (e.g., Shielded GKE Nodes, application-layer secrets encryption)
  enable_autopilot = true

  release_channel {
    channel = "REGULAR"
  }

  # --- SECURITY HARDENING: Private Cluster Configuration ---
  private_cluster_config {
    # --- CRITICAL: Fulfills "no public internet" requirement ---
    # Nodes will NOT get public IP addresses.
    enable_private_nodes = true

    # Keeps the control plane (Kube API) on a private IP
    # This is the most secure option for Cloud Shell-only access.
    enable_private_endpoint = true

    # Required IP range for the control plane to talk to private nodes
    master_ipv4_cidr_block = "172.16.0.0/28"
  }

  # --- CRITICAL FIX: ADD THIS BLOCK ---
  # This is required by Google Cloud when enable_private_endpoint is true.
  # We are authorizing the cluster's own subnet to access the private endpoint.
  master_authorized_networks_config {
    cidr_blocks {
      display_name = "cluster-subnet"
      cidr_block   = google_compute_subnetwork.cluster-subnet.ip_cidr_range
    }
  }

  workload_identity_config {
    workload_pool = "${data.google_project.project.project_id}.svc.id.goog"
  }

  # --- GKE CONFIGURATION ---
  cluster_autoscaling {
    auto_provisioning_defaults {
      service_account = google_service_account.default.email
    }
  }

  # BEST PRACTICE: Use GKE-specific logging & monitoring
  logging_service    = "logging.googleapis.com/kubernetes"
  monitoring_service = "monitoring.googleapis.com/kubernetes"

  enable_l4_ilb_subsetting = true

  # --- NETWORK FIXES ---
  network    = google_compute_network.default.id
  # <-- FIX: Correctly references "cluster-subnet"
  subnetwork = google_compute_subnetwork.cluster-subnet.id

  ip_allocation_policy {
    stack_type = "IPV4_IPV6"
    # <-- FIX: Correctly references the named ranges from the subnet
    services_secondary_range_name = google_compute_subnetwork.cluster-subnet.secondary_ip_range[0].range_name
    cluster_secondary_range_name  = google_compute_subnetwork.cluster-subnet.secondary_ip_range[1].range_name
  }

  #Quick spin up and down
  deletion_protection = false
}