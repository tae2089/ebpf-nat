//go:build linux
// +build linux

package metrics

import (
	"net"
	"testing"

	"github.com/imtaebin/ebpf-nat/internal/bpf"
	"github.com/cilium/ebpf/rlimit"
)

func TestMetricsMapExists(t *testing.T) {
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatal(err)
	}

	spec, err := bpf.LoadNat()
	if err != nil {
		t.Fatal(err)
	}

	if _, ok := spec.Maps["metrics_map"]; !ok {
		t.Error("metrics_map not found in BPF spec")
	}
}

func TestMetricsIncrement(t *testing.T) {
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
	objs.SnatConfigMap.Update(uint32(0), bpf.NatSnatConfig{
		ExternalIp: ipToUint32(externalIP),
	}, 0)

	// Prepare an egress UDP packet
	packet := []byte{
		0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
		0x08, 0x00,
		0x45, 0x00, 0x00, 0x28,
		0x00, 0x00, 0x40, 0x00,
		0x40, 0x11, 0x00, 0x00,
		192, 168, 1, 10,
		8, 8, 8, 8,
		0x30, 0x39,
		0x00, 0x35,
		0x00, 0x14,
		0x00, 0x00,
	}

	// Run the program
	ret, _, err := objs.TcNatProg.Test(packet)
	if err != nil {
		t.Fatal(err)
	}
	if ret != 0 {
		t.Errorf("Expected return value 0, got %d", ret)
	}

	// Check metrics
	key := bpf.NatMetricsKey{
		Protocol:  17, // UDP
		Direction: 1,  // Egress
		Action:    0,  // Translated
	}
	
	// PERCPU map returns a slice of values
	var values []bpf.NatMetricsValue
	if err := objs.MetricsMap.Lookup(key, &values); err != nil {
		t.Fatalf("Failed to lookup metrics: %v", err)
	}

	var totalPackets uint64
	for _, v := range values {
		totalPackets += v.Packets
	}

	if totalPackets != 1 {
		t.Errorf("Expected 1 packet in metrics, got %d", totalPackets)
	}
}

func ipToUint32(ip net.IP) uint32 {
	ip = ip.To4()
	if ip == nil {
		return 0
	}
	return binaryLittleEndianUint32(ip)
}

func binaryLittleEndianUint32(b []byte) uint32 {
	_ = b[3] // bounds check hint to compiler; see golang.org/issue/14808
	return uint32(b[0]) | uint32(b[1])<<8 | uint32(b[2])<<16 | uint32(b[3])<<24
}
