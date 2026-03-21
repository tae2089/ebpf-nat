# Plan: Session Management (Aging and Cleanup)

## Phase 1: Go User-Space GC Implementation
- [x] Task: Create `internal/nat/gc.go` to house the garbage collection logic.
- [x] Task: Implement `MapScanner` to iterate over `conntrack_map`.
- [x] Task: Implement timeout evaluation logic comparing `last_seen` against current time (adjusted for eBPF `bpf_ktime_get_ns`).
- [x] Task: Implement bi-directional deletion (delete from `conntrack_map` and construct key to delete from `reverse_nat_map`).
- [x] Task: Conductor - User Manual Verification 'Phase 1' (Protocol in workflow.md)

## Phase 2: Configuration & Integration
- [ ] Task: Add GC interval and timeout settings (TCP/UDP) to `internal/config/config.go`.
- [ ] Task: Update `Manager.RunBackgroundTasks` in `internal/nat/manager.go` to include the GC loop.
- [ ] Task: Add a CLI flag to override the GC interval in `main.go`.
- [ ] Task: Conductor - User Manual Verification 'Phase 2' (Protocol in workflow.md)

---

### TDD Execution (per task)
1. **Red Phase:** Write failing tests for map iteration and timeout logic.
2. **Green Phase:** Implement the minimum code to pass tests.
3. **Refactor:** Improve code structure, error handling, and map deletion logic.
4. **Commit:** Follow project commit guidelines.