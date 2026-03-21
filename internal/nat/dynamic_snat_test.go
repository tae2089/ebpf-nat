//go:build linux
// +build linux

package nat

import (
	"testing"

	"github.com/imtaebin/ebpf-nat/internal/bpf"
	"github.com/cilium/ebpf/rlimit"
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
