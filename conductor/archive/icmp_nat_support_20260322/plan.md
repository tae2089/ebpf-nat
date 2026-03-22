# Plan: ICMP NAT Support

## Phase 1: eBPF Data Plane Support (Echo & ID NAT)
- [x] Task: Update `bpf/nat.c` to parse ICMP headers. [5b2f485]
- [x] Task: Implement dynamic ID allocation for ICMP Echo Request (using the existing port allocation logic). [5b2f485]
- [x] Task: Implement SNAT for outgoing ICMP Echo Request (IP + ID translation). [5b2f485]
- [x] Task: Implement DNAT for incoming ICMP Echo Reply (IP + ID translation). [5b2f485]
- [x] Task: Implement ICMP checksum recalculation logic. [5b2f485]
- [x] Task: Conductor - User Manual Verification 'Phase 1' (Protocol in workflow.md) [5b2f485]

## Phase 2: eBPF Data Plane Support (ICMP Errors & PMTU)
- [x] Task: Implement parsing of "inner" IP and L4 headers for ICMP Error messages (Type 3, 11). [6effea1]
- [x] Task: Implement translation of inner headers to match the conntrack session. [6effea1]
- [x] Task: Implement translation of the outer IP header for ICMP Error messages. [6effea1]
- [x] Task: Conductor - User Manual Verification 'Phase 2' (Protocol in workflow.md) [6effea1]

## Phase 3: Control Plane & Verification
- [x] Task: Update `internal/nat/manager.go` to handle ICMP protocol in configuration (if needed). [6effea1]
- [x] Task: Extend automated tests to include ICMP packet simulations. [6effea1]
- [x] Task: Conductor - User Manual Verification 'Phase 3' (Protocol in workflow.md) [6effea1]

## Phase: Review Fixes
- [x] Task: Apply review suggestions [6effea1]

---

### TDD Execution (per task)
1. **Red Phase:** Write failing tests for specific ICMP packet types.
2. **Green Phase:** Implement the minimum code to pass tests.
3. **Refactor:** Optimize parsing and translation logic.
4. **Commit:** Follow project commit guidelines.