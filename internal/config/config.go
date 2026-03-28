package config

import (
	"fmt"
	"net"
	"strings"
	"time"
)

type Config struct {
	Interface       string
	Masquerade      bool
	ExternalIP      string
	InternalNet     string // e.g., "192.168.1.0/24" for SAV
	IPDetectType    string // generic, aws, gcp, auto
	GCInterval      string // e.g., "1m"
	TCPTimeout      string // e.g., "24h"
	UDPTimeout      string // e.g., "5m"
	MaxMSS          uint16 // TCP MSS clamping
	MaxSessions     uint32 // Maximum NAT sessions
	BatchUpdateSize uint32 // Batch update size for session restoration
	SessionFile     string // path to save/restore sessions
	// RestorationFailureThreshold: 세션 복원 실패율 임계값 (0.0~1.0, 기본값 0.5)
	// 복원 실패율이 이 값을 초과하면 경고를 출력한다.
	// 0.0: Go zero value로 "미설정" 처리 → LoadConfig에서 기본값 0.5 사용
	// 최소 유효값은 0.01 이상 (즉시 에러를 원하면 0.01 설정), 1.0: 모든 실패 무시
	RestorationFailureThreshold float64
	// MaxSessionsPerSource: 단일 소스 IP의 최대 세션 수 (0=비활성)
	MaxSessionsPerSource uint32
	// TCPSynSentTimeout: TCP SYN 이후 응답 없는 half-open 연결의 타임아웃 (기본값 75초, 최솟값 30초)
	// reverse_nat_map 엔트리가 없는 TCP ACTIVE 세션에 적용된다.
	TCPSynSentTimeout string
	Metrics         MetricsConfig
	SNAT            []Rule
	DNAT            []Rule
}

func (c *Config) Validate() error {
	if c.Interface == "" {
		return fmt.Errorf("interface is required")
	}

	if c.ExternalIP != "" {
		ip := net.ParseIP(c.ExternalIP)
		if ip == nil {
			return fmt.Errorf("invalid external-ip: %s", c.ExternalIP)
		}
		if ip.To4() == nil {
			return fmt.Errorf("external-ip must be IPv4: %s", c.ExternalIP)
		}
	}

	if c.InternalNet != "" {
		if _, _, err := net.ParseCIDR(c.InternalNet); err != nil {
			return fmt.Errorf("invalid internal-net CIDR: %w", err)
		}
	}

	// G-5: 타임아웃 최솟값 검증
	// 너무 작은 값은 CPU 독점(GC) 또는 세션 조기 종료(TCP/UDP) 등 운영 문제를 일으킨다.
	durations := []struct {
		name   string
		value  string
		minVal time.Duration
	}{
		{"gc-interval", c.GCInterval, time.Second},
		{"tcp-timeout", c.TCPTimeout, time.Minute},
		{"udp-timeout", c.UDPTimeout, 10 * time.Second},
		{"tcp-syn-sent-timeout", c.TCPSynSentTimeout, 30 * time.Second},
	}

	for _, d := range durations {
		if d.value != "" {
			dur, err := time.ParseDuration(d.value)
			if err != nil {
				return fmt.Errorf("invalid %s duration: %w", d.name, err)
			}
			if dur <= 0 {
				return fmt.Errorf("invalid %s duration: must be positive, got %s", d.name, d.value)
			}
			if dur < d.minVal {
				return fmt.Errorf("invalid %s duration: must be at least %s, got %s", d.name, d.minVal, d.value)
			}
		}
	}

	if c.MaxSessions > 0 && c.MaxSessions < 8 {
		return fmt.Errorf("max-sessions must be at least 8, got %d", c.MaxSessions)
	}

	if c.IPDetectType != "" {
		switch c.IPDetectType {
		case "generic", "aws", "gcp", "auto":
			// valid
		default:
			return fmt.Errorf("invalid ip-detect-type: %s (must be generic, aws, gcp, or auto)", c.IPDetectType)
		}
	}

	// RestorationFailureThreshold 검증: 0.0~1.0 범위
	if c.RestorationFailureThreshold < 0.0 || c.RestorationFailureThreshold > 1.0 {
		return fmt.Errorf("invalid restoration-failure-threshold: %.2f (must be 0.0-1.0)", c.RestorationFailureThreshold)
	}

	if c.Metrics.Enabled && (c.Metrics.Port < 1 || c.Metrics.Port > 65535) {
		return fmt.Errorf("invalid metrics-port: %d (must be 1-65535)", c.Metrics.Port)
	}

	// 메트릭이 활성화되고 비-localhost 주소에 바인딩하는데 토큰이 없으면 에러
	// 토큰 없이 공개 주소에 메트릭을 노출하면 무인증으로 접근 가능해 보안 취약점이 된다.
	// 빈 주소("")는 0.0.0.0으로 바인딩되므로 localhost가 아닌 것으로 간주한다.
	if c.Metrics.Enabled && c.Metrics.BearerToken == "" {
		addr := c.Metrics.Address
		if addr == "" || !isLocalhostAddress(addr) {
			return fmt.Errorf("metrics address %q is not localhost; bearer token required for security", addr)
		}
	}

	for i, r := range c.SNAT {
		if err := r.Validate(); err != nil {
			return fmt.Errorf("invalid SNAT rule #%d: %w", i, err)
		}
	}

	for i, r := range c.DNAT {
		if err := r.Validate(); err != nil {
			return fmt.Errorf("invalid DNAT rule #%d: %w", i, err)
		}
	}

	return nil
}

type MetricsConfig struct {
	Enabled     bool
	Address     string
	Port        int
	BearerToken string // Bearer token for authentication (empty = no auth)
}

type Rule struct {
	SrcIP     string
	DstIP     string
	SrcPort   uint16
	DstPort   uint16
	Protocol  string
	TransIP   string
	TransPort uint16
}

// isLocalhostAddress는 주소 문자열이 localhost 계열인지 확인한다.
// "localhost" 문자열 또는 net.IP.IsLoopback()이 true인 주소(127.0.0.0/8, ::1 등)를 localhost로 간주한다.
func isLocalhostAddress(addr string) bool {
	if addr == "localhost" {
		return true
	}
	if ip := net.ParseIP(addr); ip != nil {
		return ip.IsLoopback()
	}
	return false
}

// validateTranslationIP는 DNAT/SNAT 번역 대상 IP가 유효한지 검증한다.
// 루프백, 멀티캐스트, 미지정, 브로드캐스트, 링크-로컬 주소는 번역 대상으로 부적절하다.
func validateTranslationIP(ip net.IP) error {
	if ip.IsLoopback() {
		return fmt.Errorf("loopback address not allowed as translation target: %s", ip)
	}
	if ip.IsMulticast() {
		return fmt.Errorf("multicast address not allowed as translation target: %s", ip)
	}
	if ip.IsUnspecified() {
		return fmt.Errorf("unspecified address not allowed as translation target: %s", ip)
	}
	if ip.Equal(net.IPv4bcast) {
		return fmt.Errorf("broadcast address not allowed as translation target: %s", ip)
	}
	if ip.IsLinkLocalUnicast() {
		return fmt.Errorf("link-local address not allowed as translation target: %s", ip)
	}
	return nil
}

func (r *Rule) Validate() error {
	if r.SrcIP != "" && r.SrcIP != "0.0.0.0" && net.ParseIP(r.SrcIP) == nil {
		return fmt.Errorf("invalid src-ip: %s", r.SrcIP)
	}
	if r.DstIP != "" && r.DstIP != "0.0.0.0" && net.ParseIP(r.DstIP) == nil {
		return fmt.Errorf("invalid dst-ip: %s", r.DstIP)
	}
	if r.TransIP == "" {
		return fmt.Errorf("trans-ip is required")
	}
	transIP := net.ParseIP(r.TransIP)
	if transIP == nil {
		return fmt.Errorf("invalid trans-ip: %s", r.TransIP)
	}
	if transIP.To4() == nil {
		return fmt.Errorf("trans-ip must be IPv4: %s", r.TransIP)
	}
	// 특수 용도 주소는 번역 대상으로 부적절하다
	if err := validateTranslationIP(transIP); err != nil {
		return fmt.Errorf("invalid trans-ip: %w", err)
	}
	if !strings.EqualFold(r.Protocol, "tcp") && !strings.EqualFold(r.Protocol, "udp") {
		return fmt.Errorf("invalid protocol: %s (must be tcp or udp)", r.Protocol)
	}
	return nil
}
