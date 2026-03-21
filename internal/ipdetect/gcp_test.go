package ipdetect

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestGCPDetector_GetPublicIP(t *testing.T) {
	mux := http.NewServeMux()
	
	// Mock GCP IP endpoint
	mux.HandleFunc("/computeMetadata/v1/instance/network-interfaces/0/access-configs/0/external-ip", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Metadata-Flavor") != "Google" {
			t.Error("missing or invalid Metadata-Flavor header")
		}
		w.Write([]byte("5.6.7.8"))
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
