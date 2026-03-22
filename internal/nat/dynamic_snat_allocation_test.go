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
	packet := []byte{
		// Ethernet
		0x00, 0x00, 0x00, 0x00, 0x00, 0x02, // dst
		0x00, 0x00, 0x00, 0x00, 0x00, 0x01, // src
		0x08, 0x00, // type: IPv4
		// IP
		0x45, 0x00, 0x00, 0x28,
		0x00, 0x00, 0x40, 0x00,
		0x40, 0x11, 0x00, 0x00, // UDP
		192, 168, 1, 10,       // src
		8, 8, 8, 8,            // dst
		// UDP
		0x30, 0x39, // src port 12345
		0x00, 0x35, // dst port 53
		0x00, 0x14,
		0x00, 0x00,
	}

	ret, out, err := objs.TcNatEgress.Test(packet)
	if err != nil {
		t.Fatal(err)
	}

	if ret != 0 {
		t.Errorf("Expected return value 0, got %d", ret)
	}

	srcIP := net.IP(out[26:30])
	if !srcIP.Equal(externalIP.To4()) {
		t.Errorf("Expected source IP %v, got %v", externalIP, srcIP)
	}

	srcPort := binary.BigEndian.Uint16(out[34:36])
	if srcPort < EPHEMERAL_PORT_START || srcPort > EPHEMERAL_PORT_END {
		t.Errorf("Expected source port in range, got %d", srcPort)
	}

	// Verify conntrack entries - USE HOST BYTE ORDER for ports in keys
	key := bpf.NatNatKey{
		SrcIp:    ipToUint32(net.ParseIP("192.168.1.10")),
		DstIp:    ipToUint32(net.ParseIP("8.8.8.8")),
		SrcPort:  12345,
		DstPort:  53,
		Protocol: 17,
	}
	var entry bpf.NatNatEntry
	if err := objs.ConntrackMap.Lookup(key, &entry); err != nil {
		t.Errorf("Failed to find conntrack entry: %v", err)
	}

	// Verify reverse conntrack entry
	revKey := bpf.NatNatKey{
		SrcIp:    ipToUint32(net.ParseIP("8.8.8.8")),
		DstIp:    ipToUint32(externalIP),
		SrcPort:  53,
		DstPort:  srcPort,
		Protocol: 17,
	}
	var revEntry bpf.NatNatEntry
	if err := objs.ReverseNatMap.Lookup(revKey, &revEntry); err != nil {
		t.Errorf("Failed to find reverse conntrack entry: %v", err)
	}
}
