//go:build linux
// +build linux

package nat

import (
	"context"
	"syscall"
	"testing"
	"time"

	"github.com/imtaebin/ebpf-nat/internal/bpf"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
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