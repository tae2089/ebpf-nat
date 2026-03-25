package config

import (
	"net"
	"testing"
)

func TestConfig_Validate(t *testing.T) {
	tests := []struct {
		name    string
		config  Config
		wantErr bool
	}{
		{
			name: "valid config",
			config: Config{
				Interface:   "eth0",
				ExternalIP:  "1.2.3.4",
				InternalNet: "192.168.1.0/24",
				GCInterval:  "1m",
				TCPTimeout:  "24h",
				UDPTimeout:  "5m",
			},
			wantErr: false,
		},
		{
			name: "missing interface",
			config: Config{
				ExternalIP: "1.2.3.4",
			},
			wantErr: true,
		},
		{
			name: "invalid external-ip",
			config: Config{
				Interface:  "eth0",
				ExternalIP: "invalid-ip",
			},
			wantErr: true,
		},
		{
			name: "invalid internal-net",
			config: Config{
				Interface:   "eth0",
				InternalNet: "192.168.1.0/100",
			},
			wantErr: true,
		},
		{
			name: "invalid duration",
			config: Config{
				Interface:  "eth0",
				GCInterval: "invalid-duration",
			},
			wantErr: true,
		},
		{
			name: "invalid SNAT rule",
			config: Config{
				Interface: "eth0",
				SNAT: []Rule{
					{
						SrcIP:    "invalid-ip",
						Protocol: "tcp",
					},
				},
			},
			wantErr: true,
		},
		{
			name: "invalid DNAT rule protocol",
			config: Config{
				Interface: "eth0",
				DNAT: []Rule{
					{
						Protocol: "invalid",
					},
				},
			},
			wantErr: true,
		},
		{
			name: "invalid metrics port zero",
			config: Config{
				Interface: "eth0",
				Metrics: MetricsConfig{
					Enabled: true,
					Port:    0,
				},
			},
			wantErr: true,
		},
		{
			name: "invalid metrics port too high",
			config: Config{
				Interface: "eth0",
				Metrics: MetricsConfig{
					Enabled: true,
					Port:    70000,
				},
			},
			wantErr: true,
		},
		{
			name: "valid metrics port",
			config: Config{
				Interface: "eth0",
				Metrics: MetricsConfig{
					Enabled: true,
					Port:    9090,
				},
			},
			wantErr: false,
		},
		{
			name: "IPv6 external-ip rejected",
			config: Config{
				Interface:  "eth0",
				ExternalIP: "::1",
			},
			wantErr: true,
		},
		{
			name: "DNAT rule missing trans-ip",
			config: Config{
				Interface: "eth0",
				DNAT: []Rule{
					{
						DstIP:    "1.2.3.4",
						DstPort:  80,
						Protocol: "tcp",
					},
				},
			},
			wantErr: true,
		},
		{
			name: "valid DNAT rule",
			config: Config{
				Interface: "eth0",
				DNAT: []Rule{
					{
						DstIP:     "1.2.3.4",
						DstPort:   80,
						Protocol:  "tcp",
						TransIP:   "192.168.1.100",
						TransPort: 8080,
					},
				},
			},
			wantErr: false,
		},
		{
			name: "SNAT rule with IPv6 trans-ip rejected",
			config: Config{
				Interface: "eth0",
				SNAT: []Rule{
					{
						Protocol: "tcp",
						TransIP:  "::1",
					},
				},
			},
			wantErr: true,
		},
		{
			name: "zero gc-interval rejected",
			config: Config{
				Interface:  "eth0",
				GCInterval: "0s",
			},
			wantErr: true,
		},
		{
			name: "negative tcp-timeout rejected",
			config: Config{
				Interface:  "eth0",
				TCPTimeout: "-1s",
			},
			wantErr: true,
		},
		{
			name: "max-sessions too small rejected",
			config: Config{
				Interface:   "eth0",
				MaxSessions: 3,
			},
			wantErr: true,
		},
		{
			name: "max-sessions at minimum boundary accepted",
			config: Config{
				Interface:   "eth0",
				MaxSessions: 8,
			},
			wantErr: false,
		},
		{
			name: "max-sessions zero (use default) accepted",
			config: Config{
				Interface:   "eth0",
				MaxSessions: 0,
			},
			wantErr: false,
		},
		{
			name: "valid ip-detect-type generic",
			config: Config{
				Interface:    "eth0",
				IPDetectType: "generic",
			},
			wantErr: false,
		},
		{
			name: "valid ip-detect-type aws",
			config: Config{
				Interface:    "eth0",
				IPDetectType: "aws",
			},
			wantErr: false,
		},
		{
			name: "valid ip-detect-type gcp",
			config: Config{
				Interface:    "eth0",
				IPDetectType: "gcp",
			},
			wantErr: false,
		},
		{
			name: "valid ip-detect-type auto",
			config: Config{
				Interface:    "eth0",
				IPDetectType: "auto",
			},
			wantErr: false,
		},
		{
			name: "invalid ip-detect-type rejected",
			config: Config{
				Interface:    "eth0",
				IPDetectType: "azure",
			},
			wantErr: true,
		},
		{
			name: "empty ip-detect-type accepted",
			config: Config{
				Interface:    "eth0",
				IPDetectType: "",
			},
			wantErr: false,
		},
		// G-5: 타임아웃 최솟값 검증
		{
			name: "gc-interval too small (1ns) rejected",
			config: Config{
				Interface:  "eth0",
				GCInterval: "1ns",
			},
			wantErr: true,
		},
		{
			name: "gc-interval at minimum (1s) accepted",
			config: Config{
				Interface:  "eth0",
				GCInterval: "1s",
			},
			wantErr: false,
		},
		{
			name: "tcp-timeout too small (59s) rejected",
			config: Config{
				Interface:  "eth0",
				TCPTimeout: "59s",
			},
			wantErr: true,
		},
		{
			name: "tcp-timeout at minimum (1m) accepted",
			config: Config{
				Interface:  "eth0",
				TCPTimeout: "1m",
			},
			wantErr: false,
		},
		{
			name: "udp-timeout too small (9s) rejected",
			config: Config{
				Interface:  "eth0",
				UDPTimeout: "9s",
			},
			wantErr: true,
		},
		{
			name: "udp-timeout at minimum (10s) accepted",
			config: Config{
				Interface:  "eth0",
				UDPTimeout: "10s",
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.config.Validate(); (err != nil) != tt.wantErr {
				t.Errorf("Config.Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// TestValidateTranslationIP: DNAT/SNAT transIP 입력 검증
// loopback, multicast, unspecified, broadcast, link-local 주소는
// 유효한 번역 대상이 아니므로 거부해야 한다.
func TestValidateTranslationIP(t *testing.T) {
	tests := []struct {
		name    string
		ipStr   string
		wantErr bool
	}{
		// 거부해야 하는 케이스
		{name: "loopback 127.0.0.1 거부", ipStr: "127.0.0.1", wantErr: true},
		{name: "multicast 224.0.0.1 거부", ipStr: "224.0.0.1", wantErr: true},
		{name: "unspecified 0.0.0.0 거부", ipStr: "0.0.0.0", wantErr: true},
		{name: "broadcast 255.255.255.255 거부", ipStr: "255.255.255.255", wantErr: true},
		{name: "link-local 169.254.1.1 거부", ipStr: "169.254.1.1", wantErr: true},
		// 허용해야 하는 케이스
		{name: "사설 IP 192.168.1.100 허용", ipStr: "192.168.1.100", wantErr: false},
		{name: "사설 IP 10.0.0.1 허용", ipStr: "10.0.0.1", wantErr: false},
		{name: "공인 IP 8.8.8.8 허용", ipStr: "8.8.8.8", wantErr: false},
		{name: "사설 IP 172.16.0.1 허용", ipStr: "172.16.0.1", wantErr: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ip := net.ParseIP(tt.ipStr)
			if ip == nil {
				t.Fatalf("failed to parse IP: %s", tt.ipStr)
			}
			err := validateTranslationIP(ip)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateTranslationIP(%s) error = %v, wantErr %v", tt.ipStr, err, tt.wantErr)
			}
		})
	}
}

// TestRule_Validate_TransIPSpecialAddresses: Rule.Validate()가 특수 주소 transIP를 거부하는지 검증
func TestRule_Validate_TransIPSpecialAddresses(t *testing.T) {
	tests := []struct {
		name    string
		rule    Rule
		wantErr bool
	}{
		{
			name: "loopback transIP 거부",
			rule: Rule{
				Protocol: "tcp",
				TransIP:  "127.0.0.1",
			},
			wantErr: true,
		},
		{
			name: "broadcast transIP 거부",
			rule: Rule{
				Protocol: "tcp",
				TransIP:  "255.255.255.255",
			},
			wantErr: true,
		},
		{
			name: "link-local transIP 거부",
			rule: Rule{
				Protocol: "tcp",
				TransIP:  "169.254.1.1",
			},
			wantErr: true,
		},
		{
			name: "unspecified transIP 거부",
			rule: Rule{
				Protocol: "tcp",
				TransIP:  "0.0.0.0",
			},
			wantErr: true,
		},
		{
			name: "정상 사설 IP transIP 허용",
			rule: Rule{
				Protocol: "tcp",
				TransIP:  "192.168.1.100",
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.rule.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Rule.Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// TestMetrics_NonLocalhost_NoToken_Rejected: 항목 7
// 비-localhost 주소에 메트릭을 바인딩하면서 bearer token이 없으면 에러를 반환해야 한다.
func TestMetrics_NonLocalhost_NoToken_Rejected(t *testing.T) {
	tests := []struct {
		name    string
		cfg     Config
		wantErr bool
	}{
		{
			name: "비-localhost 주소 + 토큰 없음 → 에러",
			cfg: Config{
				Interface: "eth0",
				Metrics: MetricsConfig{
					Enabled: true,
					Port:    9090,
					Address: "0.0.0.0",
				},
			},
			wantErr: true,
		},
		{
			name: "비-localhost 주소 + 토큰 있음 → 허용",
			cfg: Config{
				Interface: "eth0",
				Metrics: MetricsConfig{
					Enabled:     true,
					Port:        9090,
					Address:     "0.0.0.0",
					BearerToken: "secrettoken",
				},
			},
			wantErr: false,
		},
		{
			name: "localhost 주소 + 토큰 없음 → 허용",
			cfg: Config{
				Interface: "eth0",
				Metrics: MetricsConfig{
					Enabled: true,
					Port:    9090,
					Address: "127.0.0.1",
				},
			},
			wantErr: false,
		},
		{
			name: "::1 (IPv6 loopback) + 토큰 없음 → 허용",
			cfg: Config{
				Interface: "eth0",
				Metrics: MetricsConfig{
					Enabled: true,
					Port:    9090,
					Address: "::1",
				},
			},
			wantErr: false,
		},
		{
			name: "localhost 문자열 + 토큰 없음 → 허용",
			cfg: Config{
				Interface: "eth0",
				Metrics: MetricsConfig{
					Enabled: true,
					Port:    9090,
					Address: "localhost",
				},
			},
			wantErr: false,
		},
		{
			name: "metrics 비활성 시 주소 검사 안 함",
			cfg: Config{
				Interface: "eth0",
				Metrics: MetricsConfig{
					Enabled: false,
					Port:    9090,
					Address: "0.0.0.0",
				},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cfg.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Config.Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// TestRestorationFailureThreshold: 세션 복원 실패율 임계값 검증
func TestRestorationFailureThreshold(t *testing.T) {
	tests := []struct {
		name      string
		threshold float64
		wantErr   bool
	}{
		{name: "기본값 0.5 허용", threshold: 0.5, wantErr: false},
		{name: "0.0 (실패 즉시 에러) 허용", threshold: 0.0, wantErr: false},
		{name: "1.0 (모두 실패해도 무시) 허용", threshold: 1.0, wantErr: false},
		{name: "음수 거부", threshold: -0.1, wantErr: true},
		{name: "1.0 초과 거부", threshold: 1.1, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := Config{
				Interface:                   "eth0",
				RestorationFailureThreshold: tt.threshold,
			}
			err := cfg.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Config.Validate() with threshold=%.2f error = %v, wantErr %v",
					tt.threshold, err, tt.wantErr)
			}
		})
	}
}

// TestTCPSynSentTimeout_Validation: 항목 8
// TCPSynSentTimeout 필드 검증 - 30초 이상이어야 한다.
func TestTCPSynSentTimeout_Validation(t *testing.T) {
	tests := []struct {
		name    string
		timeout string
		wantErr bool
	}{
		{name: "기본값 빈 문자열 허용 (기본 75초 사용)", timeout: "", wantErr: false},
		{name: "30초 허용 (최솟값)", timeout: "30s", wantErr: false},
		{name: "75초 허용", timeout: "75s", wantErr: false},
		{name: "29초 거부 (최솟값 미만)", timeout: "29s", wantErr: true},
		{name: "0초 거부", timeout: "0s", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := Config{
				Interface:          "eth0",
				TCPSynSentTimeout:  tt.timeout,
			}
			err := cfg.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Config.Validate() with TCPSynSentTimeout=%q error = %v, wantErr %v",
					tt.timeout, err, tt.wantErr)
			}
		})
	}
}

