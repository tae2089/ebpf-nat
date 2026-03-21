# Plan: Automatic Public IP Detection

## Phase 1: Environment Detection & Metadata Clients
- [x] Task: Implement AWS IMDSv2 client for public IP retrieval. [923a576]
- [x] Task: Implement GCP Metadata Server client for public IP retrieval. [a870423]
- [x] Task: Implement Generic HTTP client for external IP retrieval (icanhazip.com). [1490411]
- [x] Task: Implement an 'Auto-Detector' that tries each method in sequence. [5852855]
- [x] Task: Conductor - User Manual Verification 'Phase 1' (Protocol in workflow.md) [0d40f55]

## Phase 2: Manager Integration & Background Task
- [x] Task: Update `Manager` to initialize the specific detector based on config (`generic`, `aws`, `gcp`, or `auto`). [3fe99c7]
- [x] Task: Implement periodic ticker (5 minutes) to trigger IP detection and eBPF map updates. [3fe99c7]
- [x] Task: Integrate fallback logic to private interface IP if detection fails. [3fe99c7]
- [x] Task: Add comprehensive logging for detection status. [3fe99c7]
- [x] Task: Conductor - User Manual Verification 'Phase 2' (Protocol in workflow.md) [a7bfdcd]

## Phase 3: Configuration & CLI Updates
- [x] Task: Update `internal/config` to include `IPDetectType` field. [3fe99c7]
- [x] Task: Update `main.go` to support `--ip-detect-type` flag. [a7bfdcd]
- [x] Task: (Optional) Add a CLI flag to override detection interval. [a7bfdcd]
- [x] Task: Conductor - User Manual Verification 'Phase 3' (Protocol in workflow.md) [a7bfdcd]

---

### TDD Execution (per task)
1. **Red Phase:** Write failing tests for the specific client or logic.
2. **Green Phase:** Implement the minimum code to pass tests.
3. **Refactor:** Improve code structure and logging.
4. **Commit:** Follow project commit guidelines.