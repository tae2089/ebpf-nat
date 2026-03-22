# Spec: Session Management (Aging and Cleanup)

## Overview
Implement a session aging and cleanup mechanism to actively monitor and remove inactive NAT connections from the eBPF maps. This prevents memory leaks and port exhaustion, ensuring long-term stability and efficient resource utilization without relying solely on the LRU eviction policy.

## Functional Requirements
1.  **Timestamp Tracking:**
    -   Update the `last_seen` timestamp in the eBPF `conntrack_map` and `reverse_nat_map` for every packet processed in a given session. (Already partially implemented).
2.  **User-Space Cleanup Loop (Garbage Collector):**
    -   Implement a background Go routine (Garbage Collector) that periodically scans the connection tracking maps.
    -   The scan interval should be configurable (e.g., default to 1 minute).
3.  **Protocol-Specific Timeouts:**
    -   Apply different timeout thresholds based on the protocol:
        -   **TCP:** 
            -   Established: 24 hours (or configurable).
            -   (Future enhancement: track TCP state (SYN/FIN) for shorter timeouts on closed connections).
        -   **UDP:** 
            -   General: 5 minutes (or configurable).
4.  **Map Eviction:**
    -   If a session's `last_seen` timestamp is older than its protocol's timeout threshold, safely delete the entry from *both* `conntrack_map` and `reverse_nat_map`.

## Non-Functional Requirements
-   **Low CPU/Memory Overhead:** The user-space scanning process should not consume excessive CPU. E.g., batching map iterations or yielding if necessary.
-   **Concurrency Safety:** Map deletions from user-space must not cause issues if the eBPF program is simultaneously accessing them. (eBPF map operations are inherently thread-safe).

## Acceptance Criteria
-   Connections that have been idle longer than their designated timeout are successfully removed from both eBPF maps.
-   Active connections (receiving packets) are not removed.
-   The cleanup loop runs periodically without crashing or leaking memory.
-   Timeouts are configurable via the application configuration.

## Out of Scope
-   Deep TCP state tracking (SYN, FIN, RST parsing) within eBPF. Initial implementation will rely solely on the generic `last_seen` timer.