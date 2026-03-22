# Spec: Prometheus Metrics Implementation

## Overview
Implement a Prometheus-compatible metrics endpoint to provide real-time observability into the NAT gateway's performance and state. The implementation will focus on efficiency, following AWS NAT Gateway metrics patterns, while ensuring user-space memory usage remains stable.

## Functional Requirements
1.  **Core Metrics (AWS-like):**
    -   `ebpf_nat_packets_total`: Counter of packets processed, labeled by `protocol` (TCP, UDP, ICMP), `direction` (ingress, egress), and `action` (translated, dropped, passed).
    -   `ebpf_nat_bytes_total`: Counter of total bytes processed, with the same labels as above.
    -   `ebpf_nat_active_sessions`: Gauge showing the current number of sessions in the conntrack map.
    -   `ebpf_nat_port_allocation_failures_total`: Counter of failed port allocation attempts (masquerading).
    -   `ebpf_nat_processing_latency_seconds`: Histogram of packet processing duration (if feasible with eBPF timers).
2.  **Storage & Aggregation Strategy:**
    -   Metrics will be aggregated in Go user-space.
    -   To prevent memory bloat, we will use fixed-cardinality labels (protocol, direction, action) rather than per-IP or per-session labels.
    -   eBPF maps will store the raw counts, and the Go control plane will scrape these maps periodically or on-demand during a Prometheus scrape.
3.  **Metrics Endpoint:**
    -   A dedicated HTTP server will expose metrics at `/metrics`.
    -   Default port: `9090` (configurable via YAML and CLI).
4.  **Configuration:**
    -   Add `metrics` section to YAML config: `enabled`, `port`, `address`.

## Non-Functional Requirements
-   **Memory Stability:** User-space memory should not grow linearly with traffic or session count. Aggregation must happen at a constant cardinality.
-   **Performance:** Scaping metrics should not interfere with the data plane's packet processing speed.

## Acceptance Criteria
-   `curl http://localhost:9090/metrics` returns valid Prometheus-formatted data.
-   Packet and byte counters accurately reflect processed traffic.
-   Active sessions gauge matches the actual number of entries in eBPF maps.
-   The metrics port can be changed via configuration.

## Out of Scope
-   Per-internal-IP traffic accounting (High cardinality).
-   Integration with external logging platforms (ELK, Datadog) beyond Prometheus.