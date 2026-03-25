package ipdetect

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

const (
	gcpMetadataBaseURL = "http://metadata.google.internal"
)

// GCPDetector implements the Detector interface for Google Compute Engine.
type GCPDetector struct {
	BaseURL string
	Client  *http.Client
}

func NewGCPDetector() *GCPDetector {
	return &GCPDetector{
		BaseURL: gcpMetadataBaseURL,
		Client: &http.Client{
			Timeout: 5 * time.Second,
		},
	}
}

func (d *GCPDetector) Name() string {
	return "GCP"
}

func (d *GCPDetector) GetPublicIP(ctx context.Context) (net.IP, error) {
	url := fmt.Sprintf("%s/computeMetadata/v1/instance/network-interfaces/0/access-configs/0/external-ip", d.BaseURL)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Metadata-Flavor", "Google")

	resp, err := d.Client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to get public IP from GCP: status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 256))
	if err != nil {
		return nil, err
	}

	ipStr := strings.TrimSpace(string(body))
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return nil, fmt.Errorf("invalid IP format from GCP: %s", ipStr)
	}

	return ip, nil
}
