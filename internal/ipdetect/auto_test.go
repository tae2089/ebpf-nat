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

// TestAutoDetector_SkipsInvalidPublicIP: 항목 2
// 하위 detector가 사설 IP나 loopback IP를 반환하면 ValidatePublicIP 실패 →
// 다음 detector로 넘어가야 한다.
func TestAutoDetector_SkipsInvalidPublicIP(t *testing.T) {
	tests := []struct {
		name        string
		d1IP        net.IP
		d2IP        net.IP
		expectedIP  string
		expectError bool
	}{
		{
			name:       "첫 번째 detector가 사설 IP 반환 시 두 번째로 넘어감",
			d1IP:       net.ParseIP("192.168.1.1"), // 사설 IP (ValidatePublicIP 실패)
			d2IP:       net.ParseIP("1.2.3.4"),     // 유효한 공인 IP
			expectedIP: "1.2.3.4",
		},
		{
			name:       "첫 번째 detector가 loopback 반환 시 두 번째로 넘어감",
			d1IP:       net.ParseIP("127.0.0.1"), // loopback (ValidatePublicIP 실패)
			d2IP:       net.ParseIP("5.6.7.8"),   // 유효한 공인 IP
			expectedIP: "5.6.7.8",
		},
		{
			name:        "모두 사설 IP 반환 시 에러",
			d1IP:        net.ParseIP("10.0.0.1"),   // 사설 IP
			d2IP:        net.ParseIP("172.16.0.1"), // 사설 IP
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d1 := &mockDetector{name: "d1", ip: tt.d1IP}
			d2 := &mockDetector{name: "d2", ip: tt.d2IP}
			auto := &AutoDetector{Detectors: []Detector{d1, d2}}

			ip, err := auto.GetPublicIP(context.Background())
			if tt.expectError {
				if err == nil {
					t.Error("expected error but got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if ip.String() != tt.expectedIP {
				t.Errorf("expected %s, got %s", tt.expectedIP, ip.String())
			}
		})
	}
}
