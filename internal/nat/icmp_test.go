//go:build linux
// +build linux

package nat

import (
	"encoding/binary"
	"net"
	"testing"
	"time"

	"github.com/imtaebin/ebpf-nat/internal/bpf"
	"github.com/cilium/ebpf/rlimit"
)

func TestICMPEchoSNAT(t *testing.T) {
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

	// Prepare an egress ICMP Echo Request packet from internal network (192.168.1.10)
	// Ethernet(14) + IP(20) + ICMP(8)
	packet := []byte{
		// Ethernet
		0x00, 0x00, 0x00, 0x00, 0x00, 0x02, // dst
		0x00, 0x00, 0x00, 0x00, 0x00, 0x01, // src
		0x08, 0x00, // type: IPv4
		// IP
		0x45, 0x00, 0x00, 0x1c, // v4, ihl 5, len 28 (20 IP + 8 ICMP)
		0x00, 0x00, 0x40, 0x00, // id, flags, offset
		0x40, 0x01, 0x00, 0x00, // ttl 64, proto 1 (ICMP), csum (dummy)
		192, 168, 1, 10,       // src
		8, 8, 8, 8,            // dst
		// ICMP
		0x08, 0x00, // type 8 (Echo Request), code 0
		0x00, 0x00, // checksum (dummy)
		0x12, 0x34, // identifier (ID)
		0x00, 0x01, // sequence number
	}

	// In TC, return value is the action. 0 = TC_ACT_OK.
	ret, out, err := objs.TcNatProg.Test(packet)
	if err != nil {
		t.Fatal(err)
	}

	if ret != 0 {
		t.Errorf("Expected return value 0 (TC_ACT_OK), got %d", ret)
	}

	// Verify the packet was modified
	// IPv4 src IP is at offset 14 + 12 = 26
	srcIP := net.IP(out[26:30])
	if !srcIP.Equal(externalIP.To4()) {
		t.Errorf("Expected source IP %v, got %v", externalIP, srcIP)
	}

	// Verify ICMP ID was changed to ephemeral range
	// ICMP ID is at offset 14 + 20 + 4 = 38
	icmpID := binary.BigEndian.Uint16(out[38:40])
	if icmpID < EPHEMERAL_PORT_START || icmpID > EPHEMERAL_PORT_END {
		t.Errorf("Expected ICMP ID in range %d-%d, got %d", EPHEMERAL_PORT_START, EPHEMERAL_PORT_END, icmpID)
	}
}

func TestICMPEchoDNAT(t *testing.T) {
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatal(err)
	}

	objs := bpf.NatObjects{}
	if err := bpf.LoadNatObjects(&objs, nil); err != nil {
		t.Fatal(err)
	}
	defer objs.Close()

	internalIP := net.ParseIP("192.168.1.10")
	externalIP := net.ParseIP("10.0.0.1")
	targetIP := net.ParseIP("8.8.8.8")
	originalID := uint16(0x1234)
	translatedID := uint16(40000)

	// Pre-populate conntrack maps to simulate an existing session
	// Key: Target -> Gateway (External)
	// BPF code for ICMP Echo Reply uses: 
	// key.src_ip = iph->saddr (8.8.8.8)
	// key.dst_ip = iph->daddr (10.0.0.1)
	// key.src_port = ih->un.echo.id (translatedID)
	// key.dst_port = ih->un.echo.id (translatedID)
	revKey := bpf.NatNatKey{
		SrcIp:    ipToUint32(targetIP),
		DstIp:    ipToUint32(externalIP),
		SrcPort:  htons(translatedID), 
		DstPort:  htons(translatedID),
		Protocol: 1,
	}
	revEntry := bpf.NatNatEntry{
		TranslatedIp:   ipToUint32(internalIP),
		TranslatedPort: htons(originalID),
		LastSeen:       uint64(time.Now().UnixNano()),
	}
	if err := objs.ReverseNatMap.Update(revKey, revEntry, 0); err != nil {
		t.Fatal(err)
	}

	// Prepare an ingress ICMP Echo Reply packet (Target -> Gateway)
	packet := []byte{
		// Ethernet
		0x00, 0x00, 0x00, 0x00, 0x00, 0x01, // dst
		0x00, 0x00, 0x00, 0x00, 0x00, 0x02, // src
		0x08, 0x00, // type: IPv4
		// IP
		0x45, 0x00, 0x00, 0x1c,
		0x00, 0x00, 0x40, 0x00,
		0x40, 0x01, 0x00, 0x00,
		8, 8, 8, 8,            // src
		10, 0, 0, 1,           // dst (Gateway External IP)
		// ICMP
		0x00, 0x00, // type 0 (Echo Reply), code 0
		0x00, 0x00, // checksum
		0x9c, 0x40, // identifier (ID) = 40000
		0x00, 0x01, // sequence number
	}

	ret, out, err := objs.TcNatProg.Test(packet)
	if err != nil {
		t.Fatal(err)
	}

	if ret != 0 {
		t.Errorf("Expected return value 0 (TC_ACT_OK), got %d", ret)
	}

	// Verify DNAT (Destination IP should be internalIP)
	dstIP := net.IP(out[30:34])
	if !dstIP.Equal(internalIP.To4()) {
		t.Errorf("Expected destination IP %v, got %v", internalIP, dstIP)
	}

	// Verify ICMP ID was changed back to original
	icmpID := binary.BigEndian.Uint16(out[38:40])
	if icmpID != originalID {
		t.Errorf("Expected ICMP ID %d, got %d", originalID, icmpID)
	}
}
