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
	// HTTPS를 사용하여 MITM 공격으로 external IP가 조작되는 것을 방지한다.
	// 평문 HTTP를 사용하면 공격자가 응답을 위조하여 전체 SNAT 트래픽을
	// 공격자 주소로 라우팅시킬 수 있다.
	defaultExternalIPURL = "https://icanhazip.com"

	// sanitizeMaxLen: 로그에 포함되는 외부 응답의 최대 길이.
	// 로그 인젝션 방어를 위해 40자로 제한한다.
	sanitizeMaxLen = 40
)

// ValidatePublicIP는 탐지된 외부 IP가 실제 공인 IP인지 검증한다.
// DNS 하이재킹이나 설정 오류로 loopback, 사설, 특수 용도 IP가 반환될 경우
// SNAT가 잘못 동작하는 취약점을 방어한다.
//
// 거부 조건:
//   - IPv6 주소 (NAT는 IPv4만 지원)
//   - 루프백 주소 (127.x.x.x)
//   - 사설 주소 RFC1918 (10.x, 172.16-31.x, 192.168.x)
//   - 미지정 주소 (0.0.0.0)
//   - 멀티캐스트 주소 (224.x-239.x)
//   - 링크-로컬 주소 (169.254.x.x)
func ValidatePublicIP(ip net.IP) error {
	if ip.To4() == nil {
		return fmt.Errorf("detected IP is not IPv4: %s", ip)
	}
	if ip.IsLoopback() {
		return fmt.Errorf("detected IP is a loopback address: %s", ip)
	}
	if ip.IsPrivate() {
		return fmt.Errorf("detected IP is a private (RFC1918) address: %s", ip)
	}
	if ip.IsUnspecified() {
		return fmt.Errorf("detected IP is unspecified (0.0.0.0): %s", ip)
	}
	if ip.IsMulticast() {
		return fmt.Errorf("detected IP is a multicast address: %s", ip)
	}
	if ip.IsLinkLocalUnicast() {
		return fmt.Errorf("detected IP is a link-local address: %s", ip)
	}
	return nil
}

// sanitizeExternalResponse는 외부 서비스 응답을 로그에 포함하기 안전하게 정제한다.
// 로그 인젝션 방어를 위해 다음을 수행한다:
//  1. 허용 문자(0x20-0x7E, ASCII 출력 가능 문자)만 통과시킨다.
//  2. 결과를 sanitizeMaxLen(40자)로 잘라낸다.
func sanitizeExternalResponse(s string) string {
	filtered := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		b := s[i]
		// 0x20(space) ~ 0x7E(tilde)만 허용: 제어 문자, 비ASCII 문자 모두 제거
		if b >= 0x20 && b <= 0x7E {
			filtered = append(filtered, b)
		}
	}
	if len(filtered) > sanitizeMaxLen {
		filtered = filtered[:sanitizeMaxLen]
	}
	return string(filtered)
}

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

	body, err := io.ReadAll(io.LimitReader(resp.Body, 256))
	if err != nil {
		return nil, err
	}

	ipStr := strings.TrimSpace(string(body))
	ip := net.ParseIP(ipStr)
	if ip == nil {
		// sanitize: 외부 응답을 그대로 로그에 포함하면 로그 인젝션이 발생할 수 있다.
		return nil, fmt.Errorf("invalid IP format from generic service: %s", sanitizeExternalResponse(ipStr))
	}

	return ip, nil
}
