//go:build linux
// +build linux

package nat

import (
	"encoding/binary"
	"net"
	"syscall"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/tae2089/ebpf-nat/internal/bpf"
)

func TestAddSNATRule(t *testing.T) {
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatal(err)
	}

	// Load the spec but only load the map, not the program (to avoid verifier issues in Docker)
	spec, err := bpf.LoadNat()
	if err != nil {
		t.Fatal(err)
	}

	// Create only the map
	m, err := ebpf.NewMap(spec.Maps["conntrack_map"])
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()

	// Mock NatObjects with only the map
	objs := &bpf.NatObjects{
		NatMaps: bpf.NatMaps{
			ConntrackMap: m,
		},
	}

	mgr := NewManager(objs)

	srcIP := net.ParseIP("192.168.1.10")
	dstIP := net.ParseIP("8.8.8.8")
	srcPort := uint16(12345)
	dstPort := uint16(53)
	protocol := uint8(syscall.IPPROTO_UDP)
	transIP := net.ParseIP("10.0.0.1")
	transPort := uint16(54321)

	err = mgr.AddSNATRule(srcIP, dstIP, srcPort, dstPort, protocol, transIP, transPort)
	if err != nil {
		t.Errorf("AddSNATRule failed: %v", err)
	}

	// Verify the entry in the map
	key := bpf.NatNatKey{
		SrcIp:    ipToUint32(srcIP),
		DstIp:    ipToUint32(dstIP),
		SrcPort:  srcPort,
		DstPort:  dstPort,
		Protocol: protocol,
	}

	var entry bpf.NatNatEntry
	if err := m.Lookup(key, &entry); err != nil {
		t.Errorf("Lookup failed: %v", err)
	}

	if entry.TranslatedIp != ipToUint32(transIP) {
		t.Errorf("Expected translated IP %v, got %v", ipToUint32(transIP), entry.TranslatedIp)
	}

	if entry.TranslatedPort != transPort {
		t.Errorf("Expected translated port %v, got %v", transPort, entry.TranslatedPort)
	}
}

func TestAddDNATRule(t *testing.T) {
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatal(err)
	}

	spec, err := bpf.LoadNat()
	if err != nil {
		t.Fatal(err)
	}

	m, err := ebpf.NewMap(spec.Maps["dnat_rules"])
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()

	objs := &bpf.NatObjects{
		NatMaps: bpf.NatMaps{
			DnatRules: m,
		},
	}

	mgr := NewManager(objs)

	srcIP := net.ParseIP("0.0.0.0") // Wildcard or specific
	dstIP := net.ParseIP("1.2.3.4")
	srcPort := uint16(0)
	dstPort := uint16(80)
	protocol := uint8(syscall.IPPROTO_TCP)
	transIP := net.ParseIP("192.168.1.100")
	transPort := uint16(8080)

	err = mgr.AddDNATRule(srcIP, dstIP, srcPort, dstPort, protocol, transIP, transPort)
	if err != nil {
		t.Errorf("AddDNATRule failed: %v", err)
	}

	key := bpf.NatNatKey{
		SrcIp:    ipToUint32(srcIP),
		DstIp:    ipToUint32(dstIP),
		SrcPort:  srcPort,
		DstPort:  dstPort,
		Protocol: protocol,
	}

	var entry bpf.NatNatEntry
	if err := m.Lookup(key, &entry); err != nil {
		t.Errorf("Lookup failed: %v", err)
	}

	if entry.TranslatedIp != ipToUint32(transIP) {
		t.Errorf("Expected translated IP %v, got %v", ipToUint32(transIP), entry.TranslatedIp)
	}
}

func TestAddSNATRule_IPv6Rejected(t *testing.T) {
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatal(err)
	}

	spec, err := bpf.LoadNat()
	if err != nil {
		t.Fatal(err)
	}
	m, err := ebpf.NewMap(spec.Maps["conntrack_map"])
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()

	objs := &bpf.NatObjects{NatMaps: bpf.NatMaps{ConntrackMap: m}}
	mgr := NewManager(objs)
	transIP := net.ParseIP("10.0.0.1")

	// IPv6 srcIP must be rejected (would silently become 0.0.0.0 without validation)
	err = mgr.AddSNATRule(net.ParseIP("::1"), net.ParseIP("8.8.8.8"), 0, 80, syscall.IPPROTO_TCP, transIP, 8080)
	if err == nil {
		t.Error("Expected error for IPv6 srcIP, got nil")
	}

	// IPv6 dstIP must be rejected
	err = mgr.AddSNATRule(net.ParseIP("192.168.1.1"), net.ParseIP("::1"), 0, 80, syscall.IPPROTO_TCP, transIP, 8080)
	if err == nil {
		t.Error("Expected error for IPv6 dstIP, got nil")
	}

	// nil IPs are allowed (wildcard 0.0.0.0)
	err = mgr.AddSNATRule(nil, nil, 0, 80, syscall.IPPROTO_TCP, transIP, 8080)
	if err != nil {
		t.Errorf("Expected nil error for wildcard IPs, got %v", err)
	}
}

func TestAddDNATRule_IPv6Rejected(t *testing.T) {
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatal(err)
	}

	spec, err := bpf.LoadNat()
	if err != nil {
		t.Fatal(err)
	}
	m, err := ebpf.NewMap(spec.Maps["dnat_rules"])
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()

	objs := &bpf.NatObjects{NatMaps: bpf.NatMaps{DnatRules: m}}
	mgr := NewManager(objs)
	transIP := net.ParseIP("192.168.1.100")

	// IPv6 dstIP must be rejected
	err = mgr.AddDNATRule(nil, net.ParseIP("2001:db8::1"), 0, 80, syscall.IPPROTO_TCP, transIP, 8080)
	if err == nil {
		t.Error("Expected error for IPv6 dstIP, got nil")
	}
}

func TestManagerShutdown(t *testing.T) {
	objs := &bpf.NatObjects{}
	mgr := NewManager(objs)
	mgr.Shutdown()

	srcIP := net.ParseIP("192.168.1.10")
	dstIP := net.ParseIP("8.8.8.8")
	srcPort := uint16(12345)
	dstPort := uint16(53)
	protocol := uint8(syscall.IPPROTO_UDP)
	transIP := net.ParseIP("10.0.0.1")
	transPort := uint16(54321)

	t.Run("AddSNATRule", func(t *testing.T) {
		err := mgr.AddSNATRule(srcIP, dstIP, srcPort, dstPort, protocol, transIP, transPort)
		if err != ErrManagerStopping {
			t.Errorf("expected ErrManagerStopping, got %v", err)
		}
	})

	t.Run("AddDNATRule", func(t *testing.T) {
		err := mgr.AddDNATRule(srcIP, dstIP, srcPort, dstPort, protocol, transIP, transPort)
		if err != ErrManagerStopping {
			t.Errorf("expected ErrManagerStopping, got %v", err)
		}
	})
}

func TestMapFullLRU(t *testing.T) {
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatal(err)
	}

	// Create a very small LRU map to test eviction
	m, err := ebpf.NewMap(&ebpf.MapSpec{
		Type:       ebpf.LRUHash,
		KeySize:    uint32(binary.Size(bpf.NatNatKey{})),
		ValueSize:  uint32(binary.Size(bpf.NatNatEntry{})),
		MaxEntries: 2,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()

	objs := &bpf.NatObjects{
		NatMaps: bpf.NatMaps{
			ConntrackMap: m,
		},
	}
	mgr := NewManager(objs)

	// Add 3 entries to a map of size 2
	entries := []struct {
		srcPort uint16
		transIP string
	}{
		{10001, "10.0.0.1"},
		{10002, "10.0.0.2"},
		{10003, "10.0.0.3"},
	}

	for _, e := range entries {
		err := mgr.AddSNATRule(
			net.ParseIP("192.168.1.10"), net.ParseIP("8.8.8.8"),
			e.srcPort, 53, uint8(syscall.IPPROTO_UDP),
			net.ParseIP(e.transIP), 54321,
		)
		if err != nil {
			t.Fatalf("Failed to add entry: %v", err)
		}
	}

	// Verify that only the last 2 entries remain (LRU behavior)
	var count int
	iter := m.Iterate()
	var key bpf.NatNatKey
	var value bpf.NatNatEntry
	for iter.Next(&key, &value) {
		count++
	}
	if count != 2 {
		t.Errorf("Expected 2 entries in LRU map, got %d", count)
	}

	// The first entry (10001) should be gone
	firstKey := bpf.NatNatKey{
		SrcIp:    ipToUint32(net.ParseIP("192.168.1.10")),
		DstIp:    ipToUint32(net.ParseIP("8.8.8.8")),
		SrcPort:  10001,
		DstPort:  53,
		Protocol: uint8(syscall.IPPROTO_UDP),
	}
	if err := m.Lookup(firstKey, &value); err == nil {
		t.Errorf("Expected first entry to be evicted, but it was found")
	}
}

func TestMapConflict(t *testing.T) {
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatal(err)
	}

	m, err := ebpf.NewMap(&ebpf.MapSpec{
		Type:       ebpf.Hash,
		KeySize:    uint32(binary.Size(bpf.NatNatKey{})),
		ValueSize:  uint32(binary.Size(bpf.NatNatEntry{})),
		MaxEntries: 10,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()

	objs := &bpf.NatObjects{
		NatMaps: bpf.NatMaps{
			ConntrackMap: m,
		},
	}
	mgr := NewManager(objs)

	srcIP := net.ParseIP("192.168.1.10")
	dstIP := net.ParseIP("8.8.8.8")
	srcPort := uint16(12345)
	dstPort := uint16(53)
	protocol := uint8(syscall.IPPROTO_UDP)

	// Add initial rule
	err = mgr.AddSNATRule(srcIP, dstIP, srcPort, dstPort, protocol, net.ParseIP("10.0.0.1"), 54321)
	if err != nil {
		t.Fatal(err)
	}

	// Update the same rule with different translation (Conflict/Override)
	err = mgr.AddSNATRule(srcIP, dstIP, srcPort, dstPort, protocol, net.ParseIP("10.0.0.2"), 55555)
	if err != nil {
		t.Fatal(err)
	}

	// Verify the latest value is stored
	key := bpf.NatNatKey{
		SrcIp:    ipToUint32(srcIP),
		DstIp:    ipToUint32(dstIP),
		SrcPort:  srcPort,
		DstPort:  dstPort,
		Protocol: protocol,
	}
	var value bpf.NatNatEntry
	if err := m.Lookup(key, &value); err != nil {
		t.Fatal(err)
	}

	if value.TranslatedIp != ipToUint32(net.ParseIP("10.0.0.2")) {
		t.Errorf("Expected updated IP 10.0.0.2, got %v", value.TranslatedIp)
	}
}
