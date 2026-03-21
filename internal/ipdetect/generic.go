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
	defaultExternalIPURL = "http://icanhazip.com"
)

// GenericDetector implements the Detector interface for generic HTTP services.
type GenericDetector struct {
	URL    string
	Client *http.Client
}

func NewGenericDetector() *GenericDetector {
	return &GenericDetector{
		URL: defaultExternalIPURL,
		Client: &http.Client{
			Timeout: 5 * time.Second,
		},
	}
}

func (d *GenericDetector) Name() string {
	return "Generic"
}

func (d *GenericDetector) GetPublicIP(ctx context.Context) (net.IP, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, d.URL, nil)
	if err != nil {
		return nil, err
	}

	resp, err := d.Client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to get public IP from generic service: status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	ipStr := strings.TrimSpace(string(body))
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return nil, fmt.Errorf("invalid IP format from generic service: %s", ipStr)
	}

	return ip, nil
}
