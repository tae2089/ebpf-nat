package ipdetect

import (
	"context"
	"net/http"
	"net/http/httptest"
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
