//go:build linux
// +build linux

package nat

import (
	"encoding/binary"
	"net"
	"testing"

	"github.com/imtaebin/ebpf-nat/internal/bpf"
	"github.com/cilium/ebpf/rlimit"
)

const (
	EPHEMERAL_PORT_START = 32768
	EPHEMERAL_PORT_END   = 60999
)

func TestDynamicSNATAllocation(t *testing.T) {
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatal(err)
	}

	objs := bpf.NatObjects{}
	if err := bpf.LoadNatObjects(&objs, nil); err != nil {
		t.Fatal(err)
	}
	defer objs.Close()

	// Configure SNAT external IP
	externalIP := net.ParseIP("10.0.0.1")
	err := objs.SnatConfigMap.Update(uint32(0), bpf.NatSnatConfig{
		ExternalIp: ipToUint32(externalIP),
	}, 0)
	if err != nil {
		t.Fatal(err)
	}

	// Prepare an egress UDP packet from internal network (192.168.1.10)
	// Ethernet(14) + IP(20) + UDP(8)
	packet := []byte{
		// Ethernet
		0x00, 0x00, 0x00, 0x00, 0x00, 0x02, // dst
		0x00, 0x00, 0x00, 0x00, 0x00, 0x01, // src
		0x08, 0x00, // type: IPv4
		// IP
		0x45, 0x00, 0x00, 0x28, // v4, ihl 5, len 40
		0x00, 0x00, 0x40, 0x00, // id, flags, offset
		0x40, 0x11, 0x00, 0x00, // ttl 64, proto 17 (UDP), csum (dummy)
		192, 168, 1, 10,       // src
		8, 8, 8, 8,            // dst
		// UDP
		0x30, 0x39, // src port 12345
		0x00, 0x35, // dst port 53
		0x00, 0x14, // length
		0x00, 0x00, // csum
	}

	// In TC, return value is the action. 0 = TC_ACT_OK.
	ret, out, err := objs.TcNatProg.Test(packet)
	if err != nil {
		t.Fatal(err)
	}

	if ret != 0 {
		t.Errorf("Expected return value 0 (TC_ACT_OK), got %d", ret)
	}

	// Verify the packet was modified (Source IP should be externalIP)
	// IPv4 src IP is at offset 14 + 12 = 26
	srcIP := net.IP(out[26:30])
	t.Logf("Modified packet src IP: %v", srcIP)
	if !srcIP.Equal(externalIP.To4()) {
		t.Errorf("Expected source IP %v, got %v", externalIP, srcIP)
	}

	// Verify source port was changed to ephemeral range
	// UDP src port is at offset 14 + 20 = 34
	srcPort := binary.BigEndian.Uint16(out[34:36])
	t.Logf("Modified packet src Port: %d", srcPort)
	if srcPort < EPHEMERAL_PORT_START || srcPort > EPHEMERAL_PORT_END {
		t.Errorf("Expected source port in range %d-%d, got %d", EPHEMERAL_PORT_START, EPHEMERAL_PORT_END, srcPort)
	}

	// Verify conntrack entries
	key := bpf.NatNatKey{
		SrcIp:    ipToUint32(net.ParseIP("192.168.1.10")),
		DstIp:    ipToUint32(net.ParseIP("8.8.8.8")),
		SrcPort:  htons(12345),
		DstPort:  htons(53),
		Protocol: 17,
	}
	t.Logf("Conntrack Key: %+v", key)
	var entry bpf.NatNatEntry
	if err := objs.ConntrackMap.Lookup(key, &entry); err != nil {
		t.Errorf("Failed to find conntrack entry: %v", err)
	} else {
		t.Logf("Conntrack Entry: %+v", entry)
	}
	
	if entry.TranslatedIp != ipToUint32(externalIP) {
		t.Errorf("Conntrack entry has wrong translated IP: expected %v, got %v", ipToUint32(externalIP), entry.TranslatedIp)
	}
	if entry.TranslatedPort != htons(srcPort) {
		t.Errorf("Conntrack entry has wrong translated port: expected %v, got %v", htons(srcPort), entry.TranslatedPort)
	}

	// Verify reverse conntrack entry
	revKey := bpf.NatNatKey{
		SrcIp:    ipToUint32(net.ParseIP("8.8.8.8")),
		DstIp:    ipToUint32(externalIP),
		SrcPort:  htons(53),
		DstPort:  htons(srcPort),
		Protocol: 17,
	}
	t.Logf("Reverse Key: %+v", revKey)
	var revEntry bpf.NatNatEntry
	if err := objs.ReverseNatMap.Lookup(revKey, &revEntry); err != nil {
		t.Errorf("Failed to find reverse conntrack entry: %v", err)
	} else {
		t.Logf("Reverse Entry: %+v", revEntry)
	}
}
