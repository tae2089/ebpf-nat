package nat

import (
	"log/slog"
	"math"
	"time"

	"github.com/tae2089/ebpf-nat/internal/bpf"
	"golang.org/x/sys/unix"
)

// PersistentEntry represents a single NAT session's key, value, and metadata for persistence.
type PersistentEntry struct {
	Key          bpf.NatNatKey
	Value        bpf.NatNatEntry
	IsReverse    bool
	LastSeenUnix int64 // Unix Nanoseconds
}

// SessionSnapshot is the top-level structure for NAT session persistence serialization.
type SessionSnapshot struct {
	Version   int
	CreatedAt time.Time
	Entries   []PersistentEntry
}

// getBootTimeUnixNano returns the approximate Unix timestamp of the system boot in nanoseconds.
// This is calculated as time.Now().UnixNano() - ktime_now.
func getBootTimeUnixNano() int64 {
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts); err != nil {
		// CLOCK_MONOTONIC is always available on Linux; this path is effectively unreachable.
		// Return 0 so that ktimeToUnix produces ktime values relative to the epoch,
		// which will cause restored sessions to appear very old and be filtered out —
		// a safe conservative fallback rather than silently restoring wrong sessions.
		slog.Warn("ClockGettime(CLOCK_MONOTONIC) failed, session timestamps will be incorrect", slog.Any("error", err))
		return 0
	}
	ktimeNow := ts.Nano()
	now := time.Now().UnixNano()
	return now - ktimeNow
}

// ktimeToUnix converts eBPF ktime (nanoseconds since boot) to Unix nanoseconds.
// ktime values larger than math.MaxInt64 are clamped to prevent int64 overflow;
// such values indicate a system uptime exceeding ~292 years, which is unreachable in practice.
func ktimeToUnix(ktime uint64, bootTime int64) int64 {
	if ktime > math.MaxInt64 {
		return math.MaxInt64
	}
	return bootTime + int64(ktime)
}

// unixToKtime converts Unix nanoseconds to eBPF ktime (nanoseconds since boot).
func unixToKtime(unixNano int64, bootTime int64) uint64 {
	ktime := unixNano - bootTime
	if ktime < 0 {
		return 0
	}
	return uint64(ktime)
}
