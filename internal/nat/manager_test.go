//go:build linux
// +build linux

package nat

import (
	"net"
	"testing"
	"syscall"

	"github.com/imtaebin/ebpf-nat/internal/bpf"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
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
		SrcPort:  htons(srcPort),
		DstPort:  htons(dstPort),
		Protocol: protocol,
	}

	var entry bpf.NatNatEntry
	if err := m.Lookup(key, &entry); err != nil {
		t.Errorf("Lookup failed: %v", err)
	}

	if entry.TranslatedIp != ipToUint32(transIP) {
		t.Errorf("Expected translated IP %v, got %v", ipToUint32(transIP), entry.TranslatedIp)
	}

	if entry.TranslatedPort != htons(transPort) {
		t.Errorf("Expected translated port %v, got %v", htons(transPort), entry.TranslatedPort)
	}
}
