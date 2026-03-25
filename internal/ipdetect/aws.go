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

	// G-6: TrimSpace로 앞뒤 공백을 제거한 후, 허용 문자(0x20-0x7E)만 통과시켜
	// \r\n 등의 제어 문자에 의한 HTTP 헤더 인젝션을 방지한다.
	return sanitizeExternalResponse(strings.TrimSpace(string(token))), nil
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
		// sanitize: 외부 응답을 그대로 로그에 포함하면 로그 인젝션이 발생할 수 있다.
		return nil, fmt.Errorf("invalid IP format from AWS: %s", sanitizeExternalResponse(ipStr))
	}

	return ip, nil
}
