# Plan: ICMP NAT Support

## Phase 1: eBPF Data Plane Support (Echo & ID NAT)
- [ ] Task: Update `bpf/nat.c` to parse ICMP headers.
- [ ] Task: Implement dynamic ID allocation for ICMP Echo Request (using the existing port allocation logic).
- [ ] Task: Implement SNAT for outgoing ICMP Echo Request (IP + ID translation).
- [ ] Task: Implement DNAT for incoming ICMP Echo Reply (IP + ID translation).
- [ ] Task: Implement ICMP checksum recalculation logic.
- [ ] Task: Conductor - User Manual Verification 'Phase 1' (Protocol in workflow.md)

## Phase 2: eBPF Data Plane Support (ICMP Errors & PMTU)
- [ ] Task: Implement parsing of "inner" IP and L4 headers for ICMP Error messages (Type 3, 11).
- [ ] Task: Implement translation of inner headers to match the conntrack session.
- [ ] Task: Implement translation of the outer IP header for ICMP Error messages.
- [ ] Task: Conductor - User Manual Verification 'Phase 2' (Protocol in workflow.md)

## Phase 3: Control Plane & Verification
- [ ] Task: Update `internal/nat/manager.go` to handle ICMP protocol in configuration (if needed).
- [ ] Task: Extend automated tests to include ICMP packet simulations.
- [ ] Task: Conductor - User Manual Verification 'Phase 3' (Protocol in workflow.md)

---

### TDD Execution (per task)
1. **Red Phase:** Write failing tests for specific ICMP packet types.
2. **Green Phase:** Implement the minimum code to pass tests.
3. **Refactor:** Optimize parsing and translation logic.
4. **Commit:** Follow project commit guidelines.