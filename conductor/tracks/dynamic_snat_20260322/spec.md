# Spec: Dynamic SNAT (Masquerading)

## Purpose
To enable multiple internal IP addresses to share a single external IP address by dynamically allocating ephemeral ports in the eBPF data plane.

## Key Requirements
1.  **High Performance:** Port allocation must happen within the eBPF program (`bpf/nat.c`) without user-space context switches for every new connection.
2.  **Sequential Allocation (Option A):** Use a loop-based approach (e.g., `#pragma unroll`) in eBPF to sequentially search for available ephemeral ports to minimize the "false exhaustion" problem inherent in random/hash-only allocation.
3.  **Collision Avoidance:** Ensure that the newly allocated port is not already in use by checking existing entries in the conntrack map before assigning.
4.  **Configuration:** Allow setting the external IP address and the range of ephemeral ports from the user-space Go program.

## Data Structures (Proposed)
-   **`conntrack_map`:** Existing map, but needs to fully support bidirectional tracking.
-   **`snat_config_map`:** A new BPF map (array, size 1) to hold global SNAT settings like the external IPv4 address to use.

## Workflow
1.  **Initialization:** The Go program reads configuration, determines the external IP, and populates the `snat_config_map`.
2.  **Egress Packet (New Connection):**
    -   eBPF program intercepts a packet going out.
    -   Checks `conntrack_map`. If no entry, it's a new connection.
    -   Reads `snat_config_map` to get the external IP.
    -   Calculates a hash based on the 5-tuple to determine a starting port in the ephemeral range (e.g., 32768-60999).
    -   Loops up to N times (e.g., 64). In each iteration, checks if `(external_ip, current_port)` is in use.
    -   If a free port is found, creates an entry in `conntrack_map` and modifies the packet (SNAT).
    -   If loop exhausts, drop packet.
3.  **Ingress Packet (Return Traffic):**
    -   eBPF intercepts incoming packet.
    -   Checks `conntrack_map` using destination IP/Port.
    -   If entry found, reverses the translation (DNAT back to internal IP/Port) and forwards.