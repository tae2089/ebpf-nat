package ipdetect

import (
	"context"
	"errors"
	"net"
	"testing"
)

type mockDetector struct {
	name string
	ip   net.IP
	err  error
}

func (m *mockDetector) GetPublicIP(ctx context.Context) (net.IP, error) {
	return m.ip, m.err
}

func (m *mockDetector) Name() string {
	return m.name
}

func TestAutoDetector_GetPublicIP(t *testing.T) {
	t.Run("first succeeds", func(t *testing.T) {
		d1 := &mockDetector{name: "d1", ip: net.ParseIP("1.1.1.1")}
		d2 := &mockDetector{name: "d2", ip: net.ParseIP("2.2.2.2")}
		
		auto := &AutoDetector{Detectors: []Detector{d1, d2}}
		ip, err := auto.GetPublicIP(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if ip.String() != "1.1.1.1" {
			t.Errorf("expected 1.1.1.1, got %s", ip.String())
		}
	})

	t.Run("first fails, second succeeds", func(t *testing.T) {
		d1 := &mockDetector{name: "d1", err: errors.New("fail")}
		d2 := &mockDetector{name: "d2", ip: net.ParseIP("2.2.2.2")}
		
		auto := &AutoDetector{Detectors: []Detector{d1, d2}}
		ip, err := auto.GetPublicIP(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if ip.String() != "2.2.2.2" {
			t.Errorf("expected 2.2.2.2, got %s", ip.String())
		}
	})

	t.Run("all fail", func(t *testing.T) {
		d1 := &mockDetector{name: "d1", err: errors.New("fail1")}
		d2 := &mockDetector{name: "d2", err: errors.New("fail2")}
		
		auto := &AutoDetector{Detectors: []Detector{d1, d2}}
		_, err := auto.GetPublicIP(context.Background())
		if err == nil {
			t.Error("expected error, got nil")
		}
	})
}
