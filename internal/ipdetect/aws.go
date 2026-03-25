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
	awsMetadataBaseURL = "http://169.254.169.254"
)

// AWSDetector implements the Detector interface for AWS EC2.
type AWSDetector struct {
	BaseURL string
	Client  *http.Client
}

func NewAWSDetector() *AWSDetector {
	return &AWSDetector{
		BaseURL: awsMetadataBaseURL,
		Client: &http.Client{
			Timeout: 5 * time.Second,
		},
	}
}

func (d *AWSDetector) Name() string {
	return "AWS"
}

func (d *AWSDetector) getToken(ctx context.Context) (string, error) {
	url := fmt.Sprintf("%s/latest/api/token", d.BaseURL)
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, url, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("X-aws-ec2-metadata-token-ttl-seconds", "21600")

	resp, err := d.Client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("failed to get token: status %d", resp.StatusCode)
	}

	token, err := io.ReadAll(io.LimitReader(resp.Body, 1024))
	if err != nil {
		return "", err
	}

	// TrimSpace prevents CRLF injection when token is used as an HTTP header value
	return strings.TrimSpace(string(token)), nil
}

func (d *AWSDetector) GetPublicIP(ctx context.Context) (net.IP, error) {
	token, err := d.getToken(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get AWS IMDSv2 token: %w", err)
	}

	url := fmt.Sprintf("%s/latest/meta-data/public-ipv4", d.BaseURL)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-aws-ec2-metadata-token", token)

	resp, err := d.Client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to get public IP from AWS: status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 256))
	if err != nil {
		return nil, err
	}

	ipStr := strings.TrimSpace(string(body))
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return nil, fmt.Errorf("invalid IP format from AWS: %s", ipStr)
	}

	return ip, nil
}
