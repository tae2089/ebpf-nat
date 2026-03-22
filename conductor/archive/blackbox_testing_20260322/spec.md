# Spec: End-to-End Black-box Testing

## Overview
Verify the functional correctness of the entire eBPF NAT system by running it in a simulated real-world network environment using Linux Network Namespaces. This "black-box" approach ensures that the data plane (eBPF) and control plane (Go) work together seamlessly to handle real traffic.

## Functional Requirements
1.  **Test Environment Setup:**
    -   Automatically create and tear down network namespaces: `ns-internal` and `ns-external`.
    -   Connect them using a `veth` pair, with the host (or a bridge) acting as the NAT gateway where `ebpf-nat` is attached.
2.  **End-to-End Traffic Verification:**
    -   **TCP/UDP:** Verify that a client in `ns-internal` can successfully communicate with a server in `ns-external`.
    -   **ICMP:** Verify that `ping` from `ns-internal` reaches `ns-external` and the reply is correctly translated back.
    -   **Dynamic SNAT:** Confirm that packets appearing in `ns-external` have the gateway's IP and a port from the ephemeral range.
3.  **Metrics & State Verification:**
    -   Scrape the `/metrics` endpoint after traffic flows to verify that counters (`ebpf_nat_packets_total`) reflect the actual packets sent.
    -   Inspect eBPF maps (if needed for debugging) to confirm session state.

## Non-Functional Requirements
-   **Isolation:** Tests should not interfere with the host's actual network configuration.
-   **Reproducibility:** The test environment must be easily repeatable via a single command (e.g., `make integration-test`).

## Acceptance Criteria
-   All end-to-end traffic tests (TCP, UDP, ICMP) pass within the namespace environment.
-   NAT translations are verified using `tcpdump` captures or `nc` output.
-   The test script cleans up all namespaces and interfaces upon completion.

## Out of Scope
-   Performance benchmarking (this is for functional verification).
-   Testing with actual hardware interfaces (all virtualized).