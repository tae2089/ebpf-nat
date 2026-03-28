//go:build linux

package nat

import (
	"net"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/tae2089/ebpf-nat/internal/bpf"
)

func TestNewMapsExist(t *testing.T) {
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatal(err)
	}

	spec, err := bpf.LoadNat()
	if err != nil {
		t.Fatal(err)
	}

	if _, ok := spec.Maps["reverse_nat_map"]; !ok {
		t.Error("reverse_nat_map not found in BPF spec")
	}

	if _, ok := spec.Maps["snat_config_map"]; !ok {
		t.Error("snat_config_map not found in BPF spec")
	}
}

func TestSetSNATConfig(t *testing.T) {
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatal(err)
	}

	spec, err := bpf.LoadNat()
	if err != nil {
		t.Fatal(err)
	}

	m, err := ebpf.NewMap(spec.Maps["snat_config_map"])
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()

	objs := &bpf.NatObjects{
		NatMaps: bpf.NatMaps{
			SnatConfigMap: m,
		},
	}

	mgr := NewManager(objs)
	externalIP := net.ParseIP("1.1.1.1")

	if err := mgr.SetSNATConfig(externalIP, 0); err != nil {
		t.Fatalf("SetSNATConfig failed: %v", err)
	}

	var cfg bpf.NatSnatConfig
	if err := m.Lookup(uint32(0), &cfg); err != nil {
		t.Fatalf("Lookup failed: %v", err)
	}

	if cfg.ExternalIp != ipToUint32(externalIP) {
		t.Errorf("Expected external IP %v, got %v", ipToUint32(externalIP), cfg.ExternalIp)
	}
}
