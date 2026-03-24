//go:build linux
// +build linux

package metrics

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/tae2089/ebpf-nat/internal/bpf"
)

func TestNewScraper(t *testing.T) {
	reg := prometheus.NewRegistry()
	objs := &bpf.NatObjects{}
	scraper := NewScraper(objs, nil, reg)

	if scraper == nil {
		t.Fatal("NewScraper returned nil")
	}

	// Registration happens in NewScraper if reg is not nil.
	// If it reached here without panic, it's registered (MustRegister panics on error).
}
