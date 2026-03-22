//go:build linux
// +build linux

package nat

import (
	"context"
	"encoding/binary"
	"net"
	"testing"
	"time"
	"syscall"

	"github.com/imtaebin/ebpf-nat/internal/bpf"
	"github.com/cilium/ebpf/rlimit"
)

func logPacket(t *testing.T, data []byte) {
	t.Logf("Packet Length: %d", len(data))
	for i := 0; i < len(data); i += 16 {
		end := i + 16
		if end > len(data) {
			end = len(data)
		}
		t.Logf("%04x: % x", i, data[i:end])
	}
}

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
	packet := []byte{
		// Ethernet
		0x00, 0x00, 0x00, 0x00, 0x00, 0x02, // dst
		0x00, 0x00, 0x00, 0x00, 0x00, 0x01, // src
		0x08, 0x00, // type: IPv4
		// IP
		0x45, 0x00, 0x00, 0x1c, // v4, ihl 5, len 28 (20 IP + 8 ICMP)
		0x00, 0x00, 0x40, 0x00, // id, flags, offset
		0x40, 0x01, 0x00, 0x00, // ttl 64, proto 1 (ICMP)
		192, 168, 1, 10,       // src
		8, 8, 8, 8,            // dst
		// ICMP
		0x08, 0x00, // type 8 (Echo Request), code 0
		0x00, 0x00, // checksum
		0x12, 0x34, // identifier (ID) = 0x1234
		0x00, 0x01, // sequence number
	}

	ret, out, err := objs.TcNatEgress.Test(packet)
	if err != nil {
		t.Fatal(err)
	}

	if ret != 0 {
		t.Errorf("Expected return value 0 (TC_ACT_OK), got %d", ret)
	}

	// Verify the packet was modified
	srcIP := net.IP(out[26:30])
	if !srcIP.Equal(externalIP.To4()) {
		t.Errorf("Expected source IP %v, got %v", externalIP, srcIP)
	}

	// Verify ICMP ID was changed to ephemeral range
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
	// All ports in nat_key now use host byte order
	revKey := bpf.NatNatKey{
		SrcIp:    ipToUint32(targetIP),
		DstIp:    ipToUint32(externalIP),
		SrcPort:  translatedID, 
		DstPort:  translatedID,
		Protocol: 1,
	}
	revEntry := bpf.NatNatEntry{
		TranslatedIp:   ipToUint32(internalIP),
		TranslatedPort: originalID,
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
		0x9c, 0x40, // identifier (ID) = 40000 (0x9c40)
		0x00, 0x01, // sequence number
	}

	ret, out, err := objs.TcNatIngress.Test(packet)
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

func TestICMPErrorDNAT(t *testing.T) {
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go bpf.StartTracePipeLogger(ctx)

	objs := bpf.NatObjects{}
	if err := bpf.LoadNatObjects(&objs, nil); err != nil {
		t.Fatal(err)
	}
	defer objs.Close()

	internalIP := net.ParseIP("192.168.1.10")
	externalIP := net.ParseIP("10.0.0.1")
	targetIP := net.ParseIP("8.8.8.8")
	internalPort := uint16(12345)
	externalPort := uint16(40000)
	targetPort := uint16(80)

	// Pre-populate conntrack for a TCP session
	// Both BPF and Go now use host byte order for ports in nat_key
	revKey := bpf.NatNatKey{
		SrcIp:    ipToUint32(targetIP),
		DstIp:    ipToUint32(externalIP),
		SrcPort:  targetPort,
		DstPort:  externalPort,
		Protocol: syscall.IPPROTO_TCP,
	}
	revEntry := bpf.NatNatEntry{
		TranslatedIp:   ipToUint32(internalIP),
		TranslatedPort: internalPort,
		LastSeen:       uint64(time.Now().UnixNano()),
	}
	if err := objs.ReverseNatMap.Update(revKey, revEntry, 0); err != nil {
		t.Fatal(err)
	}
	t.Logf("Setup session mapping: %v:%d -> %v:%d (Protocol: TCP)", internalIP, internalPort, externalIP, externalPort)

	// Prepare an ingress ICMP Error packet (Target -> Gateway)
	// Outer: IP(8.8.8.8 -> 10.0.0.1) + ICMP(Type 3, Code 4)
	// Inner: IP(10.0.0.1 -> 8.8.8.8) + TCP(40000 -> 80)
	packet := []byte{
		// Ethernet
		0x00, 0x00, 0x00, 0x00, 0x00, 0x01, // dst
		0x00, 0x00, 0x00, 0x00, 0x00, 0x02, // src
		0x08, 0x00, // type: IPv4
		// Outer IP
		0x45, 0x00, 0x00, 0x38, // len 56
		0x00, 0x00, 0x40, 0x00,
		0x40, 0x01, 0x00, 0x00,
		8, 8, 8, 8,            // src
		10, 0, 0, 1,           // dst (Gateway External IP)
		// ICMP Error
		0x03, 0x04, // type 3 (Dest Unreach), code 4 (Frag Needed)
		0x00, 0x00, // checksum
		0x00, 0x00, 0x05, 0xdc, // unused (4 bytes), MTU 1500
		// Inner IP Header (Original SNATed packet)
		0x45, 0x00, 0x00, 0x28,
		0x00, 0x00, 0x40, 0x00,
		0x40, 0x06, 0x00, 0x00, // TCP
		10, 0, 0, 1,           // src (Gateway External IP)
		8, 8, 8, 8,            // dst
		// Inner TCP Header (first 8 bytes)
		0x9c, 0x40, // src port 40000 (translated)
		0x00, 0x50, // dst port 80
		0x00, 0x00, 0x00, 0x00, // seq
	}

	ret, out, err := objs.TcNatIngress.Test(packet)
	if err != nil {
		t.Fatal(err)
	}

	t.Logf("Result: %d", ret)
	logPacket(t, out)

	if ret != 0 {
		t.Errorf("Expected return value 0 (TC_ACT_OK), got %d", ret)
	}

	// 1. Verify Outer DNAT
	outerDstIP := net.IP(out[30:34])
	if !outerDstIP.Equal(internalIP.To4()) {
		t.Errorf("Outer destination IP not translated: expected %v, got %v", internalIP, outerDstIP)
	}

	// 2. Verify Inner translation (Inner Source IP)
	innerSrcIP := net.IP(out[54:58])
	if !innerSrcIP.Equal(internalIP.To4()) {
		t.Errorf("Inner source IP not translated: expected %v, got %v", internalIP, innerSrcIP)
	}

	// 3. Verify Inner Port translation (Inner Source Port)
	innerSrcPort := binary.BigEndian.Uint16(out[62:64])
	if innerSrcPort != internalPort {
		t.Errorf("Inner source port not translated: expected %d, got %d", internalPort, innerSrcPort)
	}

	// Give some time for background logger to catch printk output
	time.Sleep(100 * time.Millisecond)
}
