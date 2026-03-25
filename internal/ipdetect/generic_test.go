package ipdetect

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestGenericDetector_GetPublicIP(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("9.10.11.12\n")) // Often includes a newline
	}))
	defer server.Close()

	detector := &GenericDetector{
		URL:    server.URL,
		Client: http.DefaultClient,
	}

	ip, err := detector.GetPublicIP(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if ip.String() != "9.10.11.12" {
		t.Errorf("expected 9.10.11.12, got %s", ip.String())
	}
}

// TestGenericDetector_DefaultURLIsHTTPS: S-1
// MITM 공격으로 external IP를 조작하는 것을 방지하기 위해
// 기본 URL은 반드시 HTTPS여야 한다.
func TestGenericDetector_DefaultURLIsHTTPS(t *testing.T) {
	detector := NewGenericDetector()
	if !strings.HasPrefix(detector.URL, "https://") {
		t.Errorf("default URL must use HTTPS, got: %s", detector.URL)
	}
}

// TestSanitizeExternalResponse: G-4
// 외부 서비스 응답이 로그에 그대로 기록될 때 로그 인젝션을 방지한다.
// 길이 제한(40자)과 비ASCII/제어 문자 필터링이 동작하는지 검증한다.
func TestSanitizeExternalResponse(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "정상 IP 문자열은 그대로 반환",
			input:    "1.2.3.4",
			expected: "1.2.3.4",
		},
		{
			name:     "40자 초과 입력은 잘림",
			input:    "this-is-a-very-long-string-that-exceeds-the-maximum-length-limit",
			expected: "this-is-a-very-long-string-that-exceeds-",
		},
		{
			name:     "개행 문자(\\n) 제거",
			input:    "1.2.3.4\n",
			expected: "1.2.3.4",
		},
		{
			name:     "캐리지 리턴(\\r) 제거",
			input:    "1.2.3.4\r\n",
			expected: "1.2.3.4",
		},
		{
			name:     "탭 문자 제거",
			input:    "1.2.3.4\t",
			expected: "1.2.3.4",
		},
		{
			name:     "비ASCII 문자 제거",
			input:    "1.2.3.4\xff\xfe",
			expected: "1.2.3.4",
		},
		{
			name:     "제어 문자(\x01) 제거",
			input:    "1.2.3.\x014",
			expected: "1.2.3.4",
		},
		{
			name:     "빈 문자열은 빈 문자열 반환",
			input:    "",
			expected: "",
		},
		{
			name:     "정확히 40자 입력은 그대로 반환",
			input:    "1234567890123456789012345678901234567890",
			expected: "1234567890123456789012345678901234567890",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := sanitizeExternalResponse(tt.input)
			if got != tt.expected {
				t.Errorf("sanitizeExternalResponse(%q) = %q, want %q", tt.input, got, tt.expected)
			}
		})
	}
}

// TestValidatePublicIP: 공인 IP 탐지 결과 검증
// DNS 하이재킹이나 설정 오류로 사설/특수 IP가 반환될 경우 SNAT가 잘못 동작하는 취약점 방어.
func TestValidatePublicIP(t *testing.T) {
	tests := []struct {
		name    string
		ipStr   string
		wantErr bool
	}{
		// 거부해야 하는 케이스
		{name: "loopback은 거부", ipStr: "127.0.0.1", wantErr: true},
		{name: "loopback 다른 주소도 거부", ipStr: "127.0.0.2", wantErr: true},
		{name: "RFC1918 10.x.x.x는 거부", ipStr: "10.0.0.1", wantErr: true},
		{name: "RFC1918 172.16.x.x는 거부", ipStr: "172.16.0.1", wantErr: true},
		{name: "RFC1918 192.168.x.x는 거부", ipStr: "192.168.1.1", wantErr: true},
		{name: "unspecified 0.0.0.0은 거부", ipStr: "0.0.0.0", wantErr: true},
		{name: "multicast 224.x.x.x는 거부", ipStr: "224.0.0.1", wantErr: true},
		{name: "multicast 239.x.x.x는 거부", ipStr: "239.255.255.255", wantErr: true},
		{name: "link-local 169.254.x.x는 거부", ipStr: "169.254.1.1", wantErr: true},
		// IPv6는 거부 (IPv4 only)
		{name: "IPv6 주소는 거부", ipStr: "2001:db8::1", wantErr: true},
		// 허용해야 하는 케이스
		{name: "공인 IP 8.8.8.8은 허용", ipStr: "8.8.8.8", wantErr: false},
		{name: "공인 IP 1.1.1.1은 허용", ipStr: "1.1.1.1", wantErr: false},
		{name: "공인 IP 203.0.113.1은 허용", ipStr: "203.0.113.1", wantErr: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ip := net.ParseIP(tt.ipStr)
			if ip == nil {
				t.Fatalf("failed to parse IP: %s", tt.ipStr)
			}
			err := validatePublicIP(ip)
			if (err != nil) != tt.wantErr {
				t.Errorf("validatePublicIP(%s) error = %v, wantErr %v", tt.ipStr, err, tt.wantErr)
			}
		})
	}
}
