# Spec: Automatic Public IP Detection

## Overview
Enable the eBPF NAT application to automatically detect the host's public IPv4 address when running in cloud environments (AWS, GCP) or behind a provider NAT. This ensures that SNAT (Masquerading) uses the correct public-facing IP without manual configuration.

## Functional Requirements
1.  **Multi-Provider Support:**
    -   **AWS (EC2):** Detect public IP via Instance Metadata Service (IMDSv2).
    -   **GCP (GCE):** Detect public IP via the Google Compute Engine Metadata Server.
    -   **Generic (External):** Detect public IP using common external services (e.g., `icanhazip.com`, `ifconfig.me`) as a fallback or for non-cloud environments.
2.  **Auto-Detection Logic:**
    -   The application should automatically determine which detection method to use based on the environment.
    -   No manual provider selection should be required in the configuration.
3.  **Periodic Verification:**
    -   Perform a periodic check (e.g., every 5 minutes) to ensure the detected IP is still valid and update the eBPF map if it changes.
4.  **Resilience & Fallback:**
    -   If public IP detection fails across all methods, the application should fall back to using the primary IPv4 address of the configured network interface.
    -   Detailed logging (slog) for detection attempts, successes, and failures.

## Non-Functional Requirements
-   **Low Overhead:** Detection checks should be lightweight and not impact network performance.
-   **Security:** Follow cloud-specific security practices (e.g., using IMDSv2 tokens for AWS).

## Acceptance Criteria
-   The application correctly identifies the public IP on an EC2 instance.
-   The application correctly identifies the public IP on a GCE instance.
-   The application correctly identifies the public IP in a generic environment with internet access.
-   The eBPF `snat_config_map` is updated whenever a new public IP is detected.
-   The application falls back to the private IP when no internet or metadata service is available.

## Out of Scope
-   IPv6 public address detection.
-   Dynamic interface switching (re-binding to a different interface if the IP changes).