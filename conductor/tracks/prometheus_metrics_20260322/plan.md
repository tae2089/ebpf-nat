# Plan: Prometheus Metrics Implementation

## Phase 1: eBPF Data Plane Instrumentation
- [x] Task: Update `bpf/nat.h` to include a metrics structure and a new BPF map (`metrics_map`) for global counters. [8b2d419]
- [x] Task: Update `bpf/nat.c` to increment packet and byte counters at key processing points (ingress/egress, translate/drop/pass). [8b2d419]
- [x] Task: Implement port allocation failure tracking in `bpf/nat.c`. [8b2d419]
- [x] Task: Conductor - User Manual Verification 'Phase 1' (Protocol in workflow.md) [ac14405]

## Phase 2: Go User-Space Metrics Collection
- [x] Task: Create `internal/metrics` package to interface with the eBPF `metrics_map`. [0182b1d]
- [x] Task: Implement a 'Scraper' that reads `metrics_map` and the session maps (`conntrack_map`) to provide gauge and counter data. [0182b1d]
- [x] Task: Initialize standard Prometheus registers using `prometheus/client_golang`. [0182b1d]
- [x] Task: Conductor - User Manual Verification 'Phase 2' (Protocol in workflow.md) [b81b9eb]

## Phase 3: HTTP Server & Configuration
- [x] Task: Update `internal/config` to support metrics configuration (port, enabled). [a29fc51]
- [x] Task: Implement the HTTP server in `main.go` or a dedicated service to expose `/metrics`. [a29fc51]
- [x] Task: Add CLI flags for metrics port and enable/disable. [a29fc51]
- [ ] Task: Conductor - User Manual Verification 'Phase 3' (Protocol in workflow.md)

---

### TDD Execution (per task)
1. **Red Phase:** Write failing tests verifying map structure or Prometheus registry.
2. **Green Phase:** Implement the minimum code to pass tests.
3. **Refactor:** Optimize map lookups and aggregation efficiency.
4. **Commit:** Follow project commit guidelines.