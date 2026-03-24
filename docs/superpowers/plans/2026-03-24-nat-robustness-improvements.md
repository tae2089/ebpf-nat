# NAT Robustness and Observability Improvements Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Improve NAT stability by handling map update failures in the kernel and enhancing observability and shutdown safety in the control plane.

**Architecture:** 
- **Kernel**: Check `bpf_map_update_elem` results and drop or pass packets if session creation fails.
- **Observability**: Add a new action type `ACTION_MAP_UPDATE_FAIL` to track session creation failures.
- **Control Plane**: Enhance shutdown logic with `defer` and timeouts, and implement batched map restoration to prevent kernel lockup.

**Tech Stack:** 
- C (eBPF)
- Go (Golang)
- `cilium/ebpf`
- Prometheus

---

### Task 1: Kernel Map Update Safety & Metrics

**Files:**
- Modify: `bpf/nat.h`
- Modify: `bpf/nat.c`

- [ ] **Step 1: Define `ACTION_MAP_UPDATE_FAIL` in `bpf/nat.h`**

```c
#define ACTION_MAP_UPDATE_FAIL 4
```

- [ ] **Step 2: Check map updates in `bpf/nat.c`**
- Wrap `bpf_map_update_elem` calls.
- If it fails, call `update_metrics(..., ACTION_MAP_UPDATE_FAIL, ...)` and return `TC_ACT_SHOT`.

- [ ] **Step 3: Build and verify compilation**

Run: `make generate`
Expected: SUCCESS

- [ ] **Step 4: Commit**

```bash
git add bpf/nat.h bpf/nat.c
git commit -m "feat(bpf): add map update failure checking and metrics"
```

---

### Task 2: Update Metrics Scraper for Failure Counter

**Files:**
- Modify: `internal/metrics/scraper.go`

- [ ] **Step 1: Add `MapUpdateFailures` counter to Prometheus metrics**
- [ ] **Step 2: Update `Scrape()` to include the new action type**

- [ ] **Step 3: Run unit tests**

Run: `go test ./internal/metrics/... -v`
Expected: PASS

- [ ] **Step 4: Commit**

```bash
git add internal/metrics/scraper.go
git commit -m "feat(metrics): track NAT map update failures in Prometheus"
```

---

### Task 3: Robust Shutdown & Mutex Protection

**Files:**
- Modify: `internal/nat/manager.go`
- Modify: `main.go`

- [ ] **Step 1: Add state mutex and "isStopping" flag to `Manager`**
- [ ] **Step 2: Ensure filter detachment in `main.go` is resilient**
- Use a `defer` or a more robust cleanup block to ensure `SaveSessions` is tried even if `FilterDel` fails.

- [ ] **Step 3: Commit**

```bash
git add internal/nat/manager.go main.go
git commit -m "fix(main): ensure robust shutdown and thread-safe manager state"
```

---

### Task 4: Batched Session Restoration

**Files:**
- Modify: `internal/nat/manager.go`

- [ ] **Step 1: Implement chunked `BatchUpdate` in `RestoreSessions`**
- Instead of one giant update, use a chunk size (e.g., 1000 entries) to avoid long kernel locks.

- [ ] **Step 2: Run integration tests**

Run: `make integration-test`
Expected: PASS

- [ ] **Step 3: Final Commit**

```bash
git commit -m "perf(nat): use chunked batch updates during session restoration"
```
