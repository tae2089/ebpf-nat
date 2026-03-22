//go:build linux
// +build linux

package metrics

import (
	"testing"

	"github.com/imtaebin/ebpf-nat/internal/bpf"
	"github.com/prometheus/client_golang/prometheus"
)

func TestNewScraper(t *testing.T) {
	reg := prometheus.NewRegistry()
	objs := &bpf.NatObjects{}
	scraper := NewScraper(objs, reg)
	
	if scraper == nil {
		t.Fatal("NewScraper returned nil")
	}
	
	// Registration happens in NewScraper if reg is not nil.
	// If it reached here without panic, it's registered (MustRegister panics on error).
}
