//go:build linux
// +build linux

package nat

import (
	"context"
	"syscall"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/tae2089/ebpf-nat/internal/bpf"
)

func TestGarbageCollector_Run(t *testing.T) {
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatal(err)
	}

	spec, err := bpf.LoadNat()
	if err != nil {
		t.Fatal(err)
	}

	conntrackMap, err := ebpf.NewMap(spec.Maps["conntrack_map"])
	if err != nil {
		t.Fatal(err)
	}
	defer conntrackMap.Close()

	reverseNatMap, err := ebpf.NewMap(spec.Maps["reverse_nat_map"])
	if err != nil {
		t.Fatal(err)
	}
	defer reverseNatMap.Close()

	objs := &bpf.NatObjects{
		NatMaps: bpf.NatMaps{
			ConntrackMap:  conntrackMap,
			ReverseNatMap: reverseNatMap,
		},
	}

	// 1. Setup Data
	now := uint64(time.Now().UnixNano())
	tcpTimeout := 24 * time.Hour
	udpTimeout := 5 * time.Minute

	// Active TCP
	activeTCPKey := bpf.NatNatKey{SrcIp: 1, DstIp: 2, SrcPort: 10, DstPort: 20, Protocol: syscall.IPPROTO_TCP}
	activeTCPEntry := bpf.NatNatEntry{TranslatedIp: 3, TranslatedPort: 30, LastSeen: now}
	conntrackMap.Update(activeTCPKey, activeTCPEntry, 0)

	// Expired TCP
	expiredTCPKey := bpf.NatNatKey{SrcIp: 4, DstIp: 5, SrcPort: 40, DstPort: 50, Protocol: syscall.IPPROTO_TCP}
	expiredTCPEntry := bpf.NatNatEntry{TranslatedIp: 6, TranslatedPort: 60, LastSeen: now - uint64(tcpTimeout.Nanoseconds()) - 1000}
	conntrackMap.Update(expiredTCPKey, expiredTCPEntry, 0)

	// Also add reverse entry for expired TCP
	revExpiredTCPKey := bpf.NatNatKey{SrcIp: 5, DstIp: 6, SrcPort: 50, DstPort: 60, Protocol: syscall.IPPROTO_TCP}
	revExpiredTCPEntry := bpf.NatNatEntry{TranslatedIp: 4, TranslatedPort: 40}
	reverseNatMap.Update(revExpiredTCPKey, revExpiredTCPEntry, 0)

	// 2. Initialize GC
	gc := NewGarbageCollector(objs, tcpTimeout, udpTimeout)

	// 3. Run GC (one pass)
	ctx := context.Background()
	if err := gc.RunOnce(ctx, now); err != nil {
		t.Fatalf("RunOnce failed: %v", err)
	}

	// 4. Verify Results
	var entry bpf.NatNatEntry

	// Active TCP should remain
	if err := conntrackMap.Lookup(activeTCPKey, &entry); err != nil {
		t.Errorf("Active TCP entry was deleted incorrectly")
	}

	// Expired TCP should be gone from conntrack
	if err := conntrackMap.Lookup(expiredTCPKey, &entry); err == nil {
		t.Errorf("Expired TCP entry was not deleted from conntrack_map")
	}

	// Expired TCP should be gone from reverse map
	if err := reverseNatMap.Lookup(revExpiredTCPKey, &entry); err == nil {
		t.Errorf("Expired TCP entry was not deleted from reverse_nat_map")
	}
}

func TestGarbageCollector_BatchRun(t *testing.T) {
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatal(err)
	}

	spec, err := bpf.LoadNat()
	if err != nil {
		t.Fatal(err)
	}

	conntrackMap, err := ebpf.NewMap(spec.Maps["conntrack_map"])
	if err != nil {
		t.Fatal(err)
	}
	defer conntrackMap.Close()

	reverseNatMap, err := ebpf.NewMap(spec.Maps["reverse_nat_map"])
	if err != nil {
		t.Fatal(err)
	}
	defer reverseNatMap.Close()

	objs := &bpf.NatObjects{
		NatMaps: bpf.NatMaps{
			ConntrackMap:  conntrackMap,
			ReverseNatMap: reverseNatMap,
		},
	}

	now := uint64(time.Now().UnixNano())
	tcpTimeout := 24 * time.Hour
	udpTimeout := 5 * time.Minute

	type session struct {
		key      bpf.NatNatKey
		entry    bpf.NatNatEntry
		revKey   bpf.NatNatKey
		expired  bool
	}

	sessions := []session{
		// Active TCP sessions (should survive GC)
		{
			key:     bpf.NatNatKey{SrcIp: 100, DstIp: 200, SrcPort: 1000, DstPort: 2000, Protocol: syscall.IPPROTO_TCP},
			entry:   bpf.NatNatEntry{TranslatedIp: 300, TranslatedPort: 3000, LastSeen: now},
			revKey:  bpf.NatNatKey{SrcIp: 200, DstIp: 300, SrcPort: 2000, DstPort: 3000, Protocol: syscall.IPPROTO_TCP},
			expired: false,
		},
		{
			key:     bpf.NatNatKey{SrcIp: 101, DstIp: 201, SrcPort: 1001, DstPort: 2001, Protocol: syscall.IPPROTO_TCP},
			entry:   bpf.NatNatEntry{TranslatedIp: 301, TranslatedPort: 3001, LastSeen: now - uint64(1*time.Hour.Nanoseconds())},
			revKey:  bpf.NatNatKey{SrcIp: 201, DstIp: 301, SrcPort: 2001, DstPort: 3001, Protocol: syscall.IPPROTO_TCP},
			expired: false,
		},
		{
			key:     bpf.NatNatKey{SrcIp: 102, DstIp: 202, SrcPort: 1002, DstPort: 2002, Protocol: syscall.IPPROTO_TCP},
			entry:   bpf.NatNatEntry{TranslatedIp: 302, TranslatedPort: 3002, LastSeen: now - uint64(23*time.Hour.Nanoseconds())},
			revKey:  bpf.NatNatKey{SrcIp: 202, DstIp: 302, SrcPort: 2002, DstPort: 3002, Protocol: syscall.IPPROTO_TCP},
			expired: false,
		},
		// Expired TCP sessions (should be deleted)
		{
			key:     bpf.NatNatKey{SrcIp: 110, DstIp: 210, SrcPort: 1100, DstPort: 2100, Protocol: syscall.IPPROTO_TCP},
			entry:   bpf.NatNatEntry{TranslatedIp: 310, TranslatedPort: 3100, LastSeen: now - uint64(tcpTimeout.Nanoseconds()) - 1000},
			revKey:  bpf.NatNatKey{SrcIp: 210, DstIp: 310, SrcPort: 2100, DstPort: 3100, Protocol: syscall.IPPROTO_TCP},
			expired: true,
		},
		{
			key:     bpf.NatNatKey{SrcIp: 111, DstIp: 211, SrcPort: 1101, DstPort: 2101, Protocol: syscall.IPPROTO_TCP},
			entry:   bpf.NatNatEntry{TranslatedIp: 311, TranslatedPort: 3101, LastSeen: now - uint64(48*time.Hour.Nanoseconds())},
			revKey:  bpf.NatNatKey{SrcIp: 211, DstIp: 311, SrcPort: 2101, DstPort: 3101, Protocol: syscall.IPPROTO_TCP},
			expired: true,
		},
		{
			key:     bpf.NatNatKey{SrcIp: 112, DstIp: 212, SrcPort: 1102, DstPort: 2102, Protocol: syscall.IPPROTO_TCP},
			entry:   bpf.NatNatEntry{TranslatedIp: 312, TranslatedPort: 3102, LastSeen: now - uint64(72*time.Hour.Nanoseconds())},
			revKey:  bpf.NatNatKey{SrcIp: 212, DstIp: 312, SrcPort: 2102, DstPort: 3102, Protocol: syscall.IPPROTO_TCP},
			expired: true,
		},
		// Active UDP sessions (should survive GC)
		{
			key:     bpf.NatNatKey{SrcIp: 120, DstIp: 220, SrcPort: 1200, DstPort: 2200, Protocol: syscall.IPPROTO_UDP},
			entry:   bpf.NatNatEntry{TranslatedIp: 320, TranslatedPort: 3200, LastSeen: now},
			revKey:  bpf.NatNatKey{SrcIp: 220, DstIp: 320, SrcPort: 2200, DstPort: 3200, Protocol: syscall.IPPROTO_UDP},
			expired: false,
		},
		{
			key:     bpf.NatNatKey{SrcIp: 121, DstIp: 221, SrcPort: 1201, DstPort: 2201, Protocol: syscall.IPPROTO_UDP},
			entry:   bpf.NatNatEntry{TranslatedIp: 321, TranslatedPort: 3201, LastSeen: now - uint64(1*time.Minute.Nanoseconds())},
			revKey:  bpf.NatNatKey{SrcIp: 221, DstIp: 321, SrcPort: 2201, DstPort: 3201, Protocol: syscall.IPPROTO_UDP},
			expired: false,
		},
		// Expired UDP sessions (should be deleted)
		{
			key:     bpf.NatNatKey{SrcIp: 130, DstIp: 230, SrcPort: 1300, DstPort: 2300, Protocol: syscall.IPPROTO_UDP},
			entry:   bpf.NatNatEntry{TranslatedIp: 330, TranslatedPort: 3300, LastSeen: now - uint64(udpTimeout.Nanoseconds()) - 1000},
			revKey:  bpf.NatNatKey{SrcIp: 230, DstIp: 330, SrcPort: 2300, DstPort: 3300, Protocol: syscall.IPPROTO_UDP},
			expired: true,
		},
		{
			key:     bpf.NatNatKey{SrcIp: 131, DstIp: 231, SrcPort: 1301, DstPort: 2301, Protocol: syscall.IPPROTO_UDP},
			entry:   bpf.NatNatEntry{TranslatedIp: 331, TranslatedPort: 3301, LastSeen: now - uint64(30*time.Minute.Nanoseconds())},
			revKey:  bpf.NatNatKey{SrcIp: 231, DstIp: 331, SrcPort: 2301, DstPort: 3301, Protocol: syscall.IPPROTO_UDP},
			expired: true,
		},
	}

	// Insert all sessions.
	// Reverse entries mirror the forward entry's LastSeen, matching BPF's behavior
	// (reverse entries are created with last_seen = bpf_ktime_get_ns() in nat.c:502).
	for _, s := range sessions {
		if err := conntrackMap.Update(s.key, s.entry, 0); err != nil {
			t.Fatalf("Failed to insert conntrack entry: %v", err)
		}
		revEntry := bpf.NatNatEntry{
			TranslatedIp:   s.key.SrcIp,
			TranslatedPort: s.key.SrcPort,
			LastSeen:       s.entry.LastSeen,
		}
		if err := reverseNatMap.Update(s.revKey, revEntry, 0); err != nil {
			t.Fatalf("Failed to insert reverse NAT entry: %v", err)
		}
	}

	// Run GC
	gc := NewGarbageCollector(objs, tcpTimeout, udpTimeout)
	if err := gc.RunOnce(context.Background(), now); err != nil {
		t.Fatalf("RunOnce failed: %v", err)
	}

	// Verify results
	var entry bpf.NatNatEntry
	for _, s := range sessions {
		connErr := conntrackMap.Lookup(s.key, &entry)
		revErr := reverseNatMap.Lookup(s.revKey, &entry)

		if s.expired {
			if connErr == nil {
				t.Errorf("Expired session not deleted from conntrack_map: key=%+v", s.key)
			}
			if revErr == nil {
				t.Errorf("Expired session not deleted from reverse_nat_map: revKey=%+v", s.revKey)
			}
		} else {
			if connErr != nil {
				t.Errorf("Active session wrongly deleted from conntrack_map: key=%+v", s.key)
			}
			if revErr != nil {
				t.Errorf("Active session wrongly deleted from reverse_nat_map: key=%+v", s.key)
			}
		}
	}
}

func TestGarbageCollector_StateAwareTimeout(t *testing.T) {
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatal(err)
	}

	spec, err := bpf.LoadNat()
	if err != nil {
		t.Fatal(err)
	}

	conntrackMap, err := ebpf.NewMap(spec.Maps["conntrack_map"])
	if err != nil {
		t.Fatal(err)
	}
	defer conntrackMap.Close()

	reverseNatMap, err := ebpf.NewMap(spec.Maps["reverse_nat_map"])
	if err != nil {
		t.Fatal(err)
	}
	defer reverseNatMap.Close()

	objs := &bpf.NatObjects{
		NatMaps: bpf.NatMaps{
			ConntrackMap:  conntrackMap,
			ReverseNatMap: reverseNatMap,
		},
	}

	now := uint64(time.Now().UnixNano())
	tcpTimeout := 24 * time.Hour
	udpTimeout := 5 * time.Minute

	// Session 1: Active TCP, 5 minutes old (should stay)
	activeKey := bpf.NatNatKey{SrcIp: 1, DstIp: 2, SrcPort: 100, DstPort: 200, Protocol: syscall.IPPROTO_TCP}
	activeEntry := bpf.NatNatEntry{TranslatedIp: 10, TranslatedPort: 1000, State: NatStateActive, LastSeen: now - uint64(5*time.Minute.Nanoseconds())}
	conntrackMap.Update(activeKey, activeEntry, 0)

	// Session 2: Closing TCP, 5 minutes old (should be evicted because closing timeout is 2m)
	closingKey := bpf.NatNatKey{SrcIp: 3, DstIp: 4, SrcPort: 300, DstPort: 400, Protocol: syscall.IPPROTO_TCP}
	closingEntry := bpf.NatNatEntry{TranslatedIp: 11, TranslatedPort: 1100, State: NatStateClosing, LastSeen: now - uint64(5*time.Minute.Nanoseconds())}
	conntrackMap.Update(closingKey, closingEntry, 0)

	// 2. Run GC
	gc := NewGarbageCollector(objs, tcpTimeout, udpTimeout)
	if err := gc.RunOnce(context.Background(), now); err != nil {
		t.Fatalf("RunOnce failed: %v", err)
	}

	// 3. Verify
	var entry bpf.NatNatEntry
	if err := conntrackMap.Lookup(activeKey, &entry); err != nil {
		t.Errorf("Active session (5m old) was incorrectly evicted")
	}

	if err := conntrackMap.Lookup(closingKey, &entry); err == nil {
		t.Errorf("Closing session (5m old) should have been evicted")
	}
}

func TestGarbageCollector_ClockSkewProtection(t *testing.T) {
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatal(err)
	}

	spec, err := bpf.LoadNat()
	if err != nil {
		t.Fatal(err)
	}

	conntrackMap, err := ebpf.NewMap(spec.Maps["conntrack_map"])
	if err != nil {
		t.Fatal(err)
	}
	defer conntrackMap.Close()

	reverseNatMap, err := ebpf.NewMap(spec.Maps["reverse_nat_map"])
	if err != nil {
		t.Fatal(err)
	}
	defer reverseNatMap.Close()

	objs := &bpf.NatObjects{
		NatMaps: bpf.NatMaps{
			ConntrackMap:  conntrackMap,
			ReverseNatMap: reverseNatMap,
		},
	}

	// Simulate clock skew: now is small, but LastSeen is in the "future"
	now := uint64(1000) // very small "now"
	tcpTimeout := 24 * time.Hour
	udpTimeout := 5 * time.Minute

	// Entry with LastSeen > now (future timestamp — clock skew scenario)
	// Without the underflow guard, now - entry.LastSeen wraps to a huge value
	// and the session would be wrongly evicted.
	futureKey := bpf.NatNatKey{SrcIp: 1, DstIp: 2, SrcPort: 10, DstPort: 20, Protocol: syscall.IPPROTO_TCP}
	futureEntry := bpf.NatNatEntry{TranslatedIp: 3, TranslatedPort: 30, LastSeen: now + 1_000_000_000} // 1 second in the future
	conntrackMap.Update(futureKey, futureEntry, 0)

	gc := NewGarbageCollector(objs, tcpTimeout, udpTimeout)
	if err := gc.RunOnce(context.Background(), now); err != nil {
		t.Fatalf("RunOnce failed: %v", err)
	}

	// The session with a future timestamp should NOT be evicted
	var entry bpf.NatNatEntry
	if err := conntrackMap.Lookup(futureKey, &entry); err != nil {
		t.Error("Session with future LastSeen (clock skew) was incorrectly evicted")
	}
}

func TestGarbageCollector_ICMPReverseKey(t *testing.T) {
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatal(err)
	}

	spec, err := bpf.LoadNat()
	if err != nil {
		t.Fatal(err)
	}

	conntrackMap, err := ebpf.NewMap(spec.Maps["conntrack_map"])
	if err != nil {
		t.Fatal(err)
	}
	defer conntrackMap.Close()

	reverseNatMap, err := ebpf.NewMap(spec.Maps["reverse_nat_map"])
	if err != nil {
		t.Fatal(err)
	}
	defer reverseNatMap.Close()

	objs := &bpf.NatObjects{
		NatMaps: bpf.NatMaps{
			ConntrackMap:  conntrackMap,
			ReverseNatMap: reverseNatMap,
		},
	}

	now := uint64(time.Now().UnixNano())
	udpTimeout := 5 * time.Minute

	// Expired ICMP session: echo_id=0x1234, allocated_port=40000
	echoID := uint16(0x1234)
	allocatedPort := uint16(40000)
	srcIP := uint32(0xC0A8010A) // 192.168.1.10
	dstIP := uint32(0x08080808) // 8.8.8.8
	extIP := uint32(0x0A000001) // 10.0.0.1

	// Forward entry: BPF stores ICMP keys with src_port=echo_id, dst_port=echo_id
	fwdKey := bpf.NatNatKey{
		SrcIp: srcIP, DstIp: dstIP,
		SrcPort: echoID, DstPort: echoID,
		Protocol: syscall.IPPROTO_ICMP,
	}
	fwdEntry := bpf.NatNatEntry{
		TranslatedIp:   extIP,
		TranslatedPort: allocatedPort,
		LastSeen:       now - uint64(udpTimeout.Nanoseconds()) - 1000,
	}
	conntrackMap.Update(fwdKey, fwdEntry, 0)

	// Reverse entry: BPF stores ICMP reverse keys with src_port=allocated, dst_port=allocated
	revKey := bpf.NatNatKey{
		SrcIp: dstIP, DstIp: extIP,
		SrcPort: allocatedPort, DstPort: allocatedPort,
		Protocol: syscall.IPPROTO_ICMP,
	}
	revEntry := bpf.NatNatEntry{
		TranslatedIp:   srcIP,
		TranslatedPort: echoID,
	}
	reverseNatMap.Update(revKey, revEntry, 0)

	// Run GC
	gc := NewGarbageCollector(objs, 24*time.Hour, udpTimeout)
	if err := gc.RunOnce(context.Background(), now); err != nil {
		t.Fatalf("RunOnce failed: %v", err)
	}

	// Both forward and reverse entries should be deleted
	var entry bpf.NatNatEntry
	if err := conntrackMap.Lookup(fwdKey, &entry); err == nil {
		t.Error("Expired ICMP forward entry was not deleted from conntrack_map")
	}
	if err := reverseNatMap.Lookup(revKey, &entry); err == nil {
		t.Error("Expired ICMP reverse entry was not deleted from reverse_nat_map")
	}
}

// TestGarbageCollector_OrphanReverseCleanup verifies that reverse_nat_map entries
// whose forward (conntrack) entry was evicted by LRU are cleaned up by GC when they expire.
// Without orphan cleanup, these entries accumulate indefinitely.
func TestGarbageCollector_OrphanReverseCleanup(t *testing.T) {
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatal(err)
	}

	spec, err := bpf.LoadNat()
	if err != nil {
		t.Fatal(err)
	}

	conntrackMap, err := ebpf.NewMap(spec.Maps["conntrack_map"])
	if err != nil {
		t.Fatal(err)
	}
	defer conntrackMap.Close()

	reverseNatMap, err := ebpf.NewMap(spec.Maps["reverse_nat_map"])
	if err != nil {
		t.Fatal(err)
	}
	defer reverseNatMap.Close()

	objs := &bpf.NatObjects{
		NatMaps: bpf.NatMaps{
			ConntrackMap:  conntrackMap,
			ReverseNatMap: reverseNatMap,
		},
	}

	now := uint64(time.Now().UnixNano())
	udpTimeout := 5 * time.Minute

	// Simulate an orphaned reverse entry: forward entry (conntrack) was LRU-evicted,
	// but the reverse entry remains in reverse_nat_map with an expired last_seen.
	orphanRevKey := bpf.NatNatKey{
		SrcIp: 0x08080808, DstIp: 0x0A000001,
		SrcPort: 53, DstPort: 50001,
		Protocol: syscall.IPPROTO_UDP,
	}
	orphanRevEntry := bpf.NatNatEntry{
		TranslatedIp:   0xC0A8010A,
		TranslatedPort: 12345,
		LastSeen:       now - uint64(udpTimeout.Nanoseconds()) - 1000, // expired
	}
	reverseNatMap.Update(orphanRevKey, orphanRevEntry, 0)

	// Note: no corresponding forward entry in conntrackMap — simulating LRU eviction

	gc := NewGarbageCollector(objs, 24*time.Hour, udpTimeout)
	if err := gc.RunOnce(context.Background(), now); err != nil {
		t.Fatalf("RunOnce failed: %v", err)
	}

	// Orphaned reverse entry should be deleted since it's expired
	var entry bpf.NatNatEntry
	if err := reverseNatMap.Lookup(orphanRevKey, &entry); err == nil {
		t.Error("Orphaned expired reverse entry was not deleted from reverse_nat_map")
	}
}
