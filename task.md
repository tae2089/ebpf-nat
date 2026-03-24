# Tasks: NAT Robustness and Observability Improvements (Completed)

- [x] **Task 5: Refine Shutdown Logic in `main.go`**
    - [x] Add timeout to the shutdown process using `context.WithTimeout`.
    - [x] Ensure signal handling block correctly transitions to cleanup.
- [x] **Task 6: Enhancements in `Manager`**
    - [x] Add unit test in `internal/nat/manager_test.go` for `isStopping` flag.
    - [x] Make `batchUpdateSize` configurable in `internal/config/config.go`.
    - [x] Add "Restoration Failures" metric to `Scraper`.

- [x] **Task 7: Concurrency and Shutdown Robustness (Code Reviewer Feedback)**
    - [x] Change `Manager.isStopping` from `bool` with `RWMutex` to `atomic.Bool`.
    - [x] Refactor `main.go` to use `sync.WaitGroup` for graceful shutdown of all components.
    - [x] Update C code `nat.c` to use `BPF_MAP_TYPE_LRU_HASH` for session maps.
    - [x] Add more edge-case tests (Map full, conflict override).
    - [x] Add CLI flags for `max-sessions` and `batch-update-size`.
    - [x] Fix `countMapEntries` in `scraper.go` to use safe `[]byte` iteration.
    - [x] Fix build error in `manager_test.go` (invalid `len()` on structs).

- [x] **Task 8: Structural and Runtime Reliability Refinements**
    - [x] Implement `Config.Validate()` for upfront parameter validation.
    - [x] Implement exponential backoff retry logic in `AutoDetector`.
    - [x] Add unit tests for config validation and IP detection retries.

- [x] **Task 9: Advanced NAT Protocol and Scalability Refinements**
    - [x] Implement State-aware TCP session tracking (Active vs Closing).
    - [x] Implement shorter timeouts for Closing TCP sessions in GC.
    - [x] Implement Egress ICMP Error NAT for DNAT and dynamic SNAT.
    - [x] Increase `PORT_SCAN_LIMIT` to 128 for better allocation success.
    - [x] Add unit test for state-aware timeout in `gc_test.go`.

- [x] **Task 10: Enterprise Network Topology Support**
    - [x] Implement VLAN (802.1Q/802.1AD) tag detection and support in BPF.
    - [x] Refactor BPF helpers to use dynamic offsets for L3/L4 headers.
    - [x] Verify BPF Verifier compatibility with new offset logic.
