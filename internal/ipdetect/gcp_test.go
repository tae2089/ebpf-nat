package ipdetect

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestGCPDetector_GetPublicIP(t *testing.T) {
	mux := http.NewServeMux()

	// Mock GCP IP endpoint — returns IP with trailing newline (common in HTTP responses)
	mux.HandleFunc("/computeMetadata/v1/instance/network-interfaces/0/access-configs/0/external-ip", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Metadata-Flavor") != "Google" {
			t.Error("missing or invalid Metadata-Flavor header")
		}
		w.Write([]byte("5.6.7.8\n"))
	})

	server := httptest.NewServer(mux)
	defer server.Close()

	detector := &GCPDetector{
		BaseURL: server.URL,
		Client:  http.DefaultClient,
	}

	ip, err := detector.GetPublicIP(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if ip.String() != "5.6.7.8" {
		t.Errorf("expected 5.6.7.8, got %s", ip.String())
	}
}

// TestGCPDetector_InvalidIP_Sanitized: 항목 1
// GCP 응답이 유효하지 않은 IP 문자열(제어 문자 포함)인 경우,
// 에러 메시지에 sanitize된 문자열이 포함되어야 한다 (로그 인젝션 방지).
func TestGCPDetector_InvalidIP_Sanitized(t *testing.T) {
	mux := http.NewServeMux()
	// 제어 문자(개행, 탭)를 포함한 악의적인 응답
	mux.HandleFunc("/computeMetadata/v1/instance/network-interfaces/0/access-configs/0/external-ip", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("not-an-ip\x0aInjected: evil\x0d"))
	})

	server := httptest.NewServer(mux)
	defer server.Close()

	detector := &GCPDetector{
		BaseURL: server.URL,
		Client:  http.DefaultClient,
	}

	_, err := detector.GetPublicIP(context.Background())
	if err == nil {
		t.Fatal("expected error for invalid IP, got nil")
	}

	errMsg := err.Error()
	// 제어 문자(0x0a, 0x0d)가 에러 메시지에 포함되어서는 안 된다
	if strings.Contains(errMsg, "\x0a") || strings.Contains(errMsg, "\x0d") {
		t.Errorf("error message contains unsanitized control characters: %q", errMsg)
	}
	// sanitize된 결과(not-an-ip 부분)는 포함되어야 한다
	if !strings.Contains(errMsg, "not-an-ip") {
		t.Errorf("error message should contain sanitized IP string, got: %q", errMsg)
	}
}
