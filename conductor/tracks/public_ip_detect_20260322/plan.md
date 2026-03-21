# Plan: Automatic Public IP Detection

## Phase 1: Environment Detection & Metadata Clients
- [ ] Task: Implement AWS IMDSv2 client for public IP retrieval.
- [ ] Task: Implement GCP Metadata Server client for public IP retrieval.
- [ ] Task: Implement Generic HTTP client for external IP retrieval (icanhazip.com).
- [ ] Task: Implement an 'Auto-Detector' that tries each method in sequence.
- [ ] Task: Conductor - User Manual Verification 'Phase 1' (Protocol in workflow.md)

## Phase 2: Manager Integration & Background Task
- [ ] Task: Update `Manager` to support background IP detection and map updates.
- [ ] Task: Implement periodic ticker (5 minutes) to trigger auto-detection.
- [ ] Task: Integrate fallback logic to private interface IP.
- [ ] Task: Add comprehensive logging for detection status.
- [ ] Task: Conductor - User Manual Verification 'Phase 2' (Protocol in workflow.md)

## Phase 3: Configuration & CLI Updates
- [ ] Task: Update `main.go` to initialize the detection background task if masquerading is enabled.
- [ ] Task: (Optional) Add a CLI flag to override detection interval.
- [ ] Task: Conductor - User Manual Verification 'Phase 3' (Protocol in workflow.md)

---

### TDD Execution (per task)
1. **Red Phase:** Write failing tests for the specific client or logic.
2. **Green Phase:** Implement the minimum code to pass tests.
3. **Refactor:** Improve code structure and logging.
4. **Commit:** Follow project commit guidelines.