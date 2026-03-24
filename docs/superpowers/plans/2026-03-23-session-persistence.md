# Session Persistence Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement session persistence to ensure existing NAT connections are preserved across service restarts and system reboots.

**Architecture:** 
- Use `encoding/gob` for fast binary serialization of eBPF map entries.
- Convert kernel `ktime` to Unix nanoseconds during save, and back to `ktime` during restore by calculating system boot time.
- Implement atomic file writes using a temporary file and `os.Rename`.

**Tech Stack:** 
- Go (Golang)
- `cilium/ebpf` (BatchLookup, BatchUpdate)
- `encoding/gob` (Binary serialization)

---

### Task 1: Define Persistence Data Structures

**Files:**
- Create: `internal/nat/persistence.go`

- [ ] **Step 1: Define `PersistentEntry` and `SessionSnapshot` structs**

```go
package nat

import (
	"time"
	"github.com/tae2089/ebpf-nat/internal/bpf"
)

type PersistentEntry struct {
	Key          bpf.NatNatKey
	Value        bpf.NatNatEntry
	IsReverse    bool
	LastSeenUnix int64 // Unix Nanoseconds
}

type SessionSnapshot struct {
	Version   int
	CreatedAt time.Time
	Entries   []PersistentEntry
}
```

- [ ] **Step 2: Commit**

```bash
git add internal/nat/persistence.go
git commit -m "feat: define session persistence data structures"
```

---

### Task 2: Implement Time Conversion Utilities

**Files:**
- Modify: `internal/nat/persistence.go`
- Create: `internal/nat/persistence_test.go`

- [ ] **Step 1: Implement `getBootTimeUnixNano` and conversion helpers**

```go
func getBootTimeUnixNano() int64 {
	// Implementation using time.Now() and bpf_ktime_get_ns approximation or syscall
	// Simplified: bootTime = Now - ktime
	return 0 // TODO: Real implementation
}
```

- [ ] **Step 2: Write tests for time conversion**

```go
func TestTimeConversion(t *testing.T) {
    // Verify ktime -> unix -> ktime roundtrip
}
```

- [ ] **Step 3: Run tests**

Run: `go test ./internal/nat/... -v`
Expected: PASS

- [ ] **Step 4: Commit**

```bash
git add internal/nat/persistence.go internal/nat/persistence_test.go
git commit -m "feat: add time conversion utilities for persistence"
```

---

### Task 3: Implement `SaveSessions` in `Manager`

**Files:**
- Modify: `internal/nat/manager.go`

- [ ] **Step 1: Implement `SaveSessions(path string) error`**
- Iterate `ConntrackMap` and `ReverseNatMap`.
- Convert `last_seen` to Unix nano.
- Encode with `gob` to temporary file.
- Rename to final path.

- [ ] **Step 2: Commit**

```bash
git commit -m "feat: implement SaveSessions in Manager"
```

---

### Task 4: Implement `RestoreSessions` in `Manager`

**Files:**
- Modify: `internal/nat/manager.go`

- [ ] **Step 1: Implement `RestoreSessions(path string) error`**
- Read `gob` file.
- Calculate current `bootTimeUnixNano`.
- Convert `LastSeenUnix` back to `ktime`.
- Filter expired sessions.
- `BatchUpdate` maps.

- [ ] **Step 2: Commit**

```bash
git commit -m "feat: implement RestoreSessions in Manager"
```

---

### Task 5: Integrate with Main Lifecycle

**Files:**
- Modify: `main.go`

- [ ] **Step 1: Add `RestoreSessions` on startup**
- [ ] **Step 2: Add `SaveSessions` on `SIGTERM`/`SIGINT`**

- [ ] **Step 3: Commit**

```bash
git commit -m "feat: integrate session persistence with application lifecycle"
```

---

### Task 6: End-to-End Verification

- [ ] **Step 1: Run integration test**
- Generate traffic -> Stop service -> Check file exists -> Start service -> Check session restored.

- [ ] **Step 2: Final Commit**

```bash
git commit -m "test: verify session persistence end-to-end"
```
