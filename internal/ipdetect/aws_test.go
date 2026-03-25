package ipdetect

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestAWSDetector_GetPublicIP(t *testing.T) {
	mux := http.NewServeMux()

	// Mock Token endpoint — returns token with trailing newline (common in real AWS IMDS)
	mux.HandleFunc("/latest/api/token", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut {
			t.Errorf("expected PUT, got %s", r.Method)
		}
		if r.Header.Get("X-aws-ec2-metadata-token-ttl-seconds") == "" {
			t.Error("missing TTL header")
		}
		w.Write([]byte("mock-token\n"))
	})

	// Mock IP endpoint — expects exact token (no trailing newline)
	mux.HandleFunc("/latest/meta-data/public-ipv4", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-aws-ec2-metadata-token") != "mock-token" {
			t.Errorf("expected token 'mock-token', got %q", r.Header.Get("X-aws-ec2-metadata-token"))
		}
		// Return IP with trailing newline (as real IMDS does)
		w.Write([]byte("1.2.3.4\n"))
	})

	server := httptest.NewServer(mux)
	defer server.Close()

	detector := &AWSDetector{
		BaseURL: server.URL,
		Client:  http.DefaultClient,
	}

	ip, err := detector.GetPublicIP(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if ip.String() != "1.2.3.4" {
		t.Errorf("expected 1.2.3.4, got %s", ip.String())
	}
}

// TestAWSDetector_TokenFilterControlChars: G-6
// IMDS 토큰에 제어 문자(\r\n 등)가 포함되면 HTTP 헤더 인젝션이 발생할 수 있다.
// sanitizeExternalResponse가 제어 문자를 제거하는지 단위 수준에서 검증한다.
func TestAWSDetector_TokenFilterControlChars(t *testing.T) {
	tests := []struct {
		name        string
		rawToken    string
		wantNoChars string // 이 문자들이 결과에 없어야 함
		wantContain string // 결과에 이 문자열이 포함되어야 함
	}{
		{
			name:        "CRLF 포함 토큰은 제어 문자가 제거된다",
			rawToken:    "mock-token\r\nX-Injected: evil",
			wantNoChars: "\r\n",
			wantContain: "mock-token",
		},
		{
			name:        "NULL 바이트 포함 토큰은 제어 문자가 제거된다",
			rawToken:    "mock-token\x00extra",
			wantNoChars: "\x00",
			wantContain: "mock-token",
		},
		{
			name:        "기타 제어 문자 제거",
			rawToken:    "tok\x01en",
			wantNoChars: "\x01",
			wantContain: "token",
		},
		{
			name:        "trailing newline만 있는 정상 토큰",
			rawToken:    "mock-token\n",
			wantNoChars: "\n",
			wantContain: "mock-token",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// getToken() 내부의 sanitize 로직을 직접 모사
			result := sanitizeExternalResponse(strings.TrimSpace(tt.rawToken))

			if strings.ContainsAny(result, tt.wantNoChars) {
				t.Errorf("result %q still contains forbidden chars %q", result, tt.wantNoChars)
			}
			if tt.wantContain != "" && !strings.Contains(result, tt.wantContain) {
				t.Errorf("result %q should contain %q", result, tt.wantContain)
			}
		})
	}
}
