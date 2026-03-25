package ipdetect

import (
	"context"
	"net/http"
	"net/http/httptest"
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
