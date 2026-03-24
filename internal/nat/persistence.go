package nat

import (
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
		// Fallback to a very rough estimate if clock_gettime fails
		return time.Now().UnixNano()
	}
	ktimeNow := ts.Nano()
	now := time.Now().UnixNano()
	return now - ktimeNow
}

// ktimeToUnix converts eBPF ktime (nanoseconds since boot) to Unix nanoseconds.
func ktimeToUnix(ktime uint64, bootTime int64) int64 {
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
