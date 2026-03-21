package ipdetect

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestAWSDetector_GetPublicIP(t *testing.T) {
	mux := http.NewServeMux()
	
	// Mock Token endpoint
	mux.HandleFunc("/latest/api/token", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut {
			t.Errorf("expected PUT, got %s", r.Method)
		}
		if r.Header.Get("X-aws-ec2-metadata-token-ttl-seconds") == "" {
			t.Error("missing TTL header")
		}
		w.Write([]byte("mock-token"))
	})

	// Mock IP endpoint
	mux.HandleFunc("/latest/meta-data/public-ipv4", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-aws-ec2-metadata-token") != "mock-token" {
			t.Error("missing or invalid token")
		}
		w.Write([]byte("1.2.3.4"))
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
