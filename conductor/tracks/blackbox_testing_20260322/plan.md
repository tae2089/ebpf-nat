# Plan: End-to-End Black-box Testing

## Phase 1: Test Environment Automation
- [x] Task: Implement a Go-based or Bash-based test runner that creates Linux Network Namespaces (`ns-internal`, `ns-external`). [7c1c276]
- [x] Task: Set up `veth` pairs and assign IP addresses to simulate a gateway topology. [7c1c276]
- [x] Task: Implement a cleanup routine to ensure no orphaned namespaces or interfaces remain. [7c1c276]
- [x] Task: Conductor - User Manual Verification 'Phase 1' (Protocol in workflow.md) [7c1c276]

## Phase 2: Functional Test Scenarios
- [ ] Task: Implement a 'TCP Connectivity Test' using `nc` or Go's `net` package across namespaces.
- [ ] Task: Implement a 'UDP Connectivity Test' verifying SNAT translation.
- [ ] Task: Implement an 'ICMP Echo Test' across namespaces.
- [ ] Task: Implement a 'PMTU Discovery Test' by sending large packets and verifying ICMP error handling.
- [ ] Task: Conductor - User Manual Verification 'Phase 2' (Protocol in workflow.md)

## Phase 3: Observability & Integration
- [ ] Task: Integrate metrics verification into the test runner (querying `/metrics` after traffic).
- [ ] Task: Integrate the black-box tests into the `Makefile` (e.g., `make integration-test`).
- [ ] Task: Conductor - User Manual Verification 'Phase 3' (Protocol in workflow.md)

---

### TDD Execution (per task)
1. **Red Phase:** Write a test that fails due to missing environment or failed connectivity.
2. **Green Phase:** Implement the environment setup or fix the connectivity issue.
3. **Refactor:** Clean up the test runner logic and improve logging.
4. **Commit:** Follow project commit guidelines.