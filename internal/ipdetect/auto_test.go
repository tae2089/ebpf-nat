package ipdetect

import (
	"context"
	"errors"
	"net"
	"testing"
)

type mockDetector struct {
	name      string
	ip        net.IP
	err       error
	attempts  int
	failUntil int
}

func (m *mockDetector) GetPublicIP(ctx context.Context) (net.IP, error) {
	m.attempts++
	if m.attempts <= m.failUntil {
		return nil, m.err
	}
	return m.ip, nil
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
		d1 := &mockDetector{name: "d1", err: errors.New("fail"), failUntil: 3} // Fail all 3 attempts
		d2 := &mockDetector{name: "d2", ip: net.ParseIP("2.2.2.2")}
		
		auto := &AutoDetector{Detectors: []Detector{d1, d2}}
		ip, err := auto.GetPublicIP(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if ip.String() != "2.2.2.2" {
			t.Errorf("expected 2.2.2.2, got %s", ip.String())
		}
		if d1.attempts != 3 {
			t.Errorf("expected 3 attempts for d1, got %d", d1.attempts)
		}
	})

	t.Run("first fails twice then succeeds", func(t *testing.T) {
		d1 := &mockDetector{
			name:      "d1", 
			ip:        net.ParseIP("1.1.1.1"), 
			err:       errors.New("transient"), 
			failUntil: 2,
		}
		
		auto := &AutoDetector{Detectors: []Detector{d1}}
		ip, err := auto.GetPublicIP(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if ip.String() != "1.1.1.1" {
			t.Errorf("expected 1.1.1.1, got %s", ip.String())
		}
		if d1.attempts != 3 {
			t.Errorf("expected 3 attempts for d1, got %d", d1.attempts)
		}
	})

	t.Run("all fail", func(t *testing.T) {
		d1 := &mockDetector{name: "d1", err: errors.New("fail1"), failUntil: 3}
		d2 := &mockDetector{name: "d2", err: errors.New("fail2"), failUntil: 3}
		
		auto := &AutoDetector{Detectors: []Detector{d1, d2}}
		_, err := auto.GetPublicIP(context.Background())
		if err == nil {
			t.Error("expected error, got nil")
		}
		if d1.attempts != 3 || d2.attempts != 3 {
			t.Errorf("expected 3 attempts each, got d1=%d, d2=%d", d1.attempts, d2.attempts)
		}
	})
}
