package nat

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/gob"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/tae2089/ebpf-nat/internal/bpf"
	"github.com/tae2089/ebpf-nat/internal/config"
	"github.com/tae2089/ebpf-nat/internal/ipdetect"
)

var (
	ErrManagerStopping = errors.New("manager is stopping")
)

// hmacMagic는 HMAC trailer가 존재함을 나타내는 magic bytes.
// 구 형식 파일(HMAC 없음)과 구분하기 위해 사용한다.
// 형식: [gzip data][32-byte HMAC][4-byte magic "EBPF"]
var hmacMagic = []byte{0x45, 0x42, 0x50, 0x46} // "EBPF"

const hmacSize = 32    // SHA-256 output
const hmacTrailerSize = hmacSize + 4 // HMAC + magic

const (
	NatStateActive  = 0
	NatStateClosing = 1
)

type Manager struct {
	objects      *bpf.NatObjects
	ipDetector   ipdetect.Detector
	privateIP       net.IP
	tcpTimeout      time.Duration
	udpTimeout      time.Duration
	maxMSS          uint16
	internalNet     uint32
	internalMask    uint32
	batchUpdateSize             uint32
	restorationFailures         uint64
	restorationFailureThreshold float64
	hmacKeyFile                 string
	maxSessionsPerSource        uint32
	mu                  sync.RWMutex
	isStopping      atomic.Bool
}

func NewManager(objs *bpf.NatObjects) *Manager {
	return &Manager{
		objects:                     objs,
		tcpTimeout:                  24 * time.Hour,
		udpTimeout:                  5 * time.Minute,
		batchUpdateSize:             1000,
		restorationFailureThreshold: 0.5,
		hmacKeyFile:                 "/var/lib/ebpf-nat/.hmac.key",
	}
}

// Shutdown marks the manager as stopping.
func (m *Manager) Shutdown() {
	m.isStopping.Store(true)
}

func (m *Manager) LoadConfig(cfg *config.Config) error {
	if m.isStopping.Load() {
		return ErrManagerStopping
	}
	m.mu.Lock()
	// Parse timeouts
	m.tcpTimeout = 24 * time.Hour
	if cfg.TCPTimeout != "" {
		if d, err := time.ParseDuration(cfg.TCPTimeout); err == nil {
			m.tcpTimeout = d
		} else {
			slog.Warn("Failed to parse tcp-timeout, using default 24h", slog.String("value", cfg.TCPTimeout), slog.Any("error", err))
		}
	}
	m.udpTimeout = 5 * time.Minute
	if cfg.UDPTimeout != "" {
		if d, err := time.ParseDuration(cfg.UDPTimeout); err == nil {
			m.udpTimeout = d
		} else {
			slog.Warn("Failed to parse udp-timeout, using default 5m", slog.String("value", cfg.UDPTimeout), slog.Any("error", err))
		}
	}
	m.maxMSS = cfg.MaxMSS
	if cfg.BatchUpdateSize > 0 {
		m.batchUpdateSize = cfg.BatchUpdateSize
	} else {
		m.batchUpdateSize = 1000
	}

	// RestorationFailureThreshold: 0.0~1.0 범위 (기본 0.5)
	if cfg.RestorationFailureThreshold > 0 {
		m.restorationFailureThreshold = cfg.RestorationFailureThreshold
	}

	// MaxSessionsPerSource: 0이면 비활성
	m.maxSessionsPerSource = cfg.MaxSessionsPerSource

	if cfg.InternalNet != "" {
		_, ipnet, err := net.ParseCIDR(cfg.InternalNet)
		if err != nil {
			slog.Warn("Failed to parse internal_net CIDR", slog.String("value", cfg.InternalNet), slog.Any("error", err))
		} else {
			m.internalNet = ipToUint32(ipnet.IP)
			m.internalMask = binary.NativeEndian.Uint32(ipnet.Mask)
		}
	}

	// Find private IP of the interface for fallback
	iface, err := net.InterfaceByName(cfg.Interface)
	if err == nil {
		addrs, err := iface.Addrs()
		if err == nil {
			for _, addr := range addrs {
				if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
					if ip4 := ipnet.IP.To4(); ip4 != nil {
						m.privateIP = ip4
						break
					}
				}
			}
		}
	}

	if cfg.Masquerade {
		if cfg.ExternalIP != "" {
			// Use internal method to avoid deadlock (we already hold the write lock)
			if err := m.setSNATConfigLocked(net.ParseIP(cfg.ExternalIP), cfg.MaxMSS); err != nil {
				m.mu.Unlock()
				return err
			}
		} else {
			// Initialize IP detector
			switch cfg.IPDetectType {
			case "aws":
				m.ipDetector = ipdetect.NewAWSDetector()
			case "gcp":
				m.ipDetector = ipdetect.NewGCPDetector()
			case "generic":
				m.ipDetector = ipdetect.NewGenericDetector()
			case "auto", "":
				m.ipDetector = ipdetect.NewDefaultAutoDetector()
			default:
				slog.Warn("Unknown ip_detect_type, using auto", slog.String("type", cfg.IPDetectType))
				m.ipDetector = ipdetect.NewDefaultAutoDetector()
			}

			// Release lock before calling updatePublicIP (which acquires its own lock)
			maxMSS := m.maxMSS
			privateIP := m.privateIP
			m.mu.Unlock()

			if err := m.updatePublicIP(context.Background()); err != nil {
				slog.Error("Initial public IP detection failed, using private IP", slog.Any("error", err))
				if privateIP != nil {
					m.SetSNATConfig(privateIP, maxMSS)
				}
			}

			// Re-acquire for the rest of LoadConfig
			m.mu.Lock()
		}
	}
	m.mu.Unlock()

	for _, rule := range cfg.SNAT {
		proto := parseProtocol(rule.Protocol)
		if err := m.AddSNATRule(
			net.ParseIP(rule.SrcIP), net.ParseIP(rule.DstIP),
			rule.SrcPort, rule.DstPort, proto,
			net.ParseIP(rule.TransIP), rule.TransPort,
		); err != nil {
			return err
		}
	}

	for _, rule := range cfg.DNAT {
		proto := parseProtocol(rule.Protocol)
		if err := m.AddDNATRule(
			net.ParseIP(rule.SrcIP), net.ParseIP(rule.DstIP),
			rule.SrcPort, rule.DstPort, proto,
			net.ParseIP(rule.TransIP), rule.TransPort,
		); err != nil {
			return err
		}
	}
	return nil
}

func (m *Manager) SetSNATConfig(externalIP net.IP, maxMSS uint16) error {
	if m.isStopping.Load() {
		return ErrManagerStopping
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.setSNATConfigLocked(externalIP, maxMSS)
}

// setSNATConfigLocked updates SNAT config in the BPF map.
// Caller must hold m.mu write lock.
func (m *Manager) setSNATConfigLocked(externalIP net.IP, maxMSS uint16) error {
	cfg := bpf.NatSnatConfig{
		ExternalIp:   ipToUint32(externalIP),
		InternalNet:  m.internalNet,
		InternalMask: m.internalMask,
		MaxMss:       maxMSS,
	}
	slog.Info("Updating SNAT configuration",
		slog.String("external_ip", externalIP.String()),
		slog.Uint64("max_mss", uint64(maxMSS)))
	return m.objects.SnatConfigMap.Update(uint32(0), cfg, 0)
}

func (m *Manager) updatePublicIP(ctx context.Context) error {
	if m.isStopping.Load() {
		return ErrManagerStopping
	}
	m.mu.RLock()
	maxMSS := m.maxMSS
	m.mu.RUnlock()

	if m.ipDetector == nil {
		return nil
	}

	ip, err := m.ipDetector.GetPublicIP(ctx)
	if err != nil {
		return err
	}

	// 탐지된 IP가 실제 공인 IP인지 검증한다.
	// DNS 하이재킹이나 IMDS 응답 조작으로 사설 IP가 반환되면 SNAT가 잘못 동작한다.
	if err := ipdetect.ValidatePublicIP(ip); err != nil {
		slog.Warn("Detected IP failed public IP validation, keeping existing external IP",
			slog.String("detected_ip", ip.String()),
			slog.Any("reason", err))
		return fmt.Errorf("invalid public IP detected: %w", err)
	}

	return m.SetSNATConfig(ip, maxMSS)
}

// RunBackgroundTasks starts periodic tasks like IP detection and garbage collection.
// Timeout values are read from the Manager's internal fields set by LoadConfig.
func (m *Manager) RunBackgroundTasks(ctx context.Context, ipDetectInterval, gcInterval time.Duration) {
	var ipTicker *time.Ticker
	var ipTickerC <-chan time.Time

	if m.ipDetector != nil {
		slog.Info("Starting background IP detection", slog.Duration("interval", ipDetectInterval))
		ipTicker = time.NewTicker(ipDetectInterval)
		defer ipTicker.Stop()
		ipTickerC = ipTicker.C
	}

	slog.Info("Starting background garbage collection", slog.Duration("interval", gcInterval))
	gcTicker := time.NewTicker(gcInterval)
	defer gcTicker.Stop()

	m.mu.RLock()
	tcpTimeout := m.tcpTimeout
	udpTimeout := m.udpTimeout
	maxSessionsPerSource := m.maxSessionsPerSource
	m.mu.RUnlock()
	gc := NewGarbageCollector(m.objects, tcpTimeout, udpTimeout)
	gc.maxSessionsPerSource = maxSessionsPerSource

	for {
		select {
		case <-ctx.Done():
			slog.Info("Stopping background tasks")
			return
		case <-ipTickerC:
			if m.isStopping.Load() {
				return
			}
			slog.Debug("Triggering periodic public IP detection")
			if err := m.updatePublicIP(ctx); err != nil {
				slog.Error("Periodic public IP detection failed", slog.Any("error", err))
			}
		case <-gcTicker.C:
			if m.isStopping.Load() {
				return
			}
			now := uint64(time.Now().UnixNano())
			if err := gc.RunOnce(ctx, now); err != nil {
				slog.Error("Garbage collection failed", slog.Any("error", err))
			}
		}
	}
}

// SaveSessions iterates through ConntrackMap and ReverseNatMap and saves the sessions to a file.
// This intentionally does not check isStopping because it is called as part of graceful shutdown
// after Shutdown() has been invoked and all background tasks (GC, IP detection) have stopped.
func (m *Manager) SaveSessions(path string) error {
	// Ensure directory exists (no lock needed)
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("failed to create session directory: %w", err)
	}

	// Phase 1: Snapshot map entries under lock (minimize lock duration)
	bootTime := getBootTimeUnixNano()
	snapshot := SessionSnapshot{
		Version:   1,
		CreatedAt: time.Now(),
		Entries:   []PersistentEntry{},
	}

	m.mu.RLock()
	var key bpf.NatNatKey
	var entry bpf.NatNatEntry
	iter := m.objects.ConntrackMap.Iterate()
	for iter.Next(&key, &entry) {
		snapshot.Entries = append(snapshot.Entries, PersistentEntry{
			Key:          key,
			Value:        entry,
			IsReverse:    false,
			LastSeenUnix: ktimeToUnix(entry.LastSeen, bootTime),
		})
	}
	if err := iter.Err(); err != nil {
		m.mu.RUnlock()
		return fmt.Errorf("error iterating conntrack_map: %w", err)
	}

	iter = m.objects.ReverseNatMap.Iterate()
	for iter.Next(&key, &entry) {
		snapshot.Entries = append(snapshot.Entries, PersistentEntry{
			Key:          key,
			Value:        entry,
			IsReverse:    true,
			LastSeenUnix: ktimeToUnix(entry.LastSeen, bootTime),
		})
	}
	iterErr := iter.Err()
	m.mu.RUnlock()

	if iterErr != nil {
		return fmt.Errorf("error iterating reverse_nat_map: %w", iterErr)
	}

	// Phase 2: Serialize snapshot to in-memory buffer for HMAC computation
	// HMAC 필드는 비워둔 채 직렬화 → 그 결과에 HMAC 계산 → HMAC trailer 추가
	snapshot.HMAC = nil // HMAC 계산 전에 필드를 비워야 한다

	var buf bytes.Buffer
	gwBuf := gzip.NewWriter(&buf)
	if err := gob.NewEncoder(gwBuf).Encode(snapshot); err != nil {
		return fmt.Errorf("failed to encode session snapshot: %w", err)
	}
	if err := gwBuf.Close(); err != nil {
		return fmt.Errorf("failed to close gzip writer: %w", err)
	}
	snapshotBytes := buf.Bytes()

	// HMAC 키 로드/생성 후 서명
	hmacKey := m.ensureHMACKey()
	var trailer []byte
	if hmacKey != nil {
		mac := computeHMAC(hmacKey, snapshotBytes)
		// Trailer 형식: [32-byte HMAC] + [4-byte magic "EBPF"]
		// magic으로 HMAC trailer 유무를 구분한다 (구 형식 파일과 호환)
		trailer = append(mac, hmacMagic...)
		slog.Debug("Session file HMAC computed", slog.Int("hmac_bytes", len(mac)))
	} else {
		slog.Warn("No HMAC key available, saving session file without integrity protection")
	}

	// Phase 3: Write to file: [gzip data][optional HMAC trailer]
	tmpFile := path + ".tmp"
	f, err := os.OpenFile(tmpFile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("failed to create temporary file: %w", err)
	}
	defer os.Remove(tmpFile) // Remove if we fail

	if _, err := f.Write(snapshotBytes); err != nil {
		f.Close()
		return fmt.Errorf("failed to write session data: %w", err)
	}

	if len(trailer) > 0 {
		if _, err := f.Write(trailer); err != nil {
			f.Close()
			return fmt.Errorf("failed to write HMAC trailer: %w", err)
		}
	}

	if err := f.Sync(); err != nil {
		f.Close()
		return fmt.Errorf("failed to sync temporary file: %w", err)
	}
	f.Close()

	if err := os.Rename(tmpFile, path); err != nil {
		return fmt.Errorf("failed to rename session file: %w", err)
	}

	slog.Info("Successfully saved NAT sessions", slog.String("path", path), slog.Int("entries", len(snapshot.Entries)))
	return nil
}

// RestoreSessions reads the session snapshot from a file and loads it into eBPF maps.
func (m *Manager) RestoreSessions(path string) error {
	if m.isStopping.Load() {
		return ErrManagerStopping
	}

	// Read timeout and batch size values under lock to avoid data race
	m.mu.RLock()
	tcpTimeout := m.tcpTimeout
	udpTimeout := m.udpTimeout
	batchSize := m.batchUpdateSize
	m.mu.RUnlock()

	bootTime := getBootTimeUnixNano()
	nowUnix := time.Now().UnixNano()

	rawData, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			slog.Info("No session file found, skipping restoration", slog.String("path", path))
			return nil
		}
		return fmt.Errorf("failed to open session file: %w", err)
	}

	// 파일 형식 감지: 파일 끝 4바이트가 magic("EBPF")이면 HMAC trailer 포함
	// 구 형식 파일(HMAC 없음)과 호환된다.
	var snapshotBytes []byte
	var storedMAC []byte
	hasHMAC := false

	if len(rawData) >= hmacTrailerSize {
		tailMagic := rawData[len(rawData)-4:]
		if bytes.Equal(tailMagic, hmacMagic) {
			// HMAC trailer 발견: [gzip data][32-byte HMAC][4-byte magic]
			storedMAC = rawData[len(rawData)-hmacTrailerSize : len(rawData)-4]
			snapshotBytes = rawData[:len(rawData)-hmacTrailerSize]
			hasHMAC = true
		}
	}
	if !hasHMAC {
		// 구 형식: HMAC trailer 없음
		snapshotBytes = rawData
	}

	// HMAC 검증
	hmacKey := m.loadHMACKey()
	if hmacKey != nil && hasHMAC {
		expectedMAC := computeHMAC(hmacKey, snapshotBytes)
		if !hmac.Equal(storedMAC, expectedMAC) {
			return fmt.Errorf("session file HMAC verification failed: file may have been tampered with")
		}
		slog.Debug("Session file HMAC verified successfully")
	} else if hmacKey != nil && !hasHMAC {
		// 키는 있는데 HMAC이 없는 파일 → 이전 버전 파일이나 HMAC 없이 저장된 파일
		slog.Warn("Session file has no HMAC signature; skipping integrity check (possible legacy file)")
	} else if hmacKey == nil && hasHMAC {
		// 키가 없는데 HMAC이 있는 파일 → 키를 찾을 수 없어 검증 불가
		slog.Warn("Cannot verify session file HMAC: no HMAC key available")
	} else {
		// 키도 없고 HMAC도 없는 파일 → 신규 설치 또는 키 없이 저장된 파일
		slog.Warn("Session file has no HMAC signature and no key configured; restoring without integrity check")
	}

	// gzip+gob 디코딩
	var snapshot SessionSnapshot
	gr, err := gzip.NewReader(bytes.NewReader(snapshotBytes))
	if err != nil {
		return fmt.Errorf("failed to create gzip reader: %w", err)
	}
	defer gr.Close()

	// Limit decompressed size to 256MB to prevent decompression bombs
	const maxDecompressedSize = 256 * 1024 * 1024
	limitedReader := io.LimitReader(gr, maxDecompressedSize)
	decoder := gob.NewDecoder(limitedReader)
	if err := decoder.Decode(&snapshot); err != nil {
		return fmt.Errorf("failed to decode session snapshot: %w", err)
	}

	if snapshot.Version != 1 {
		return fmt.Errorf("unsupported session snapshot version %d (expected 1)", snapshot.Version)
	}

	// Filter and prepare batch updates
	var conntrackKeys []bpf.NatNatKey
	var conntrackValues []bpf.NatNatEntry
	var reverseKeys []bpf.NatNatKey
	var reverseValues []bpf.NatNatEntry

	for _, entry := range snapshot.Entries {
		// Convert Unix nanosecond timestamp back to ktime
		entry.Value.LastSeen = unixToKtime(entry.LastSeenUnix, bootTime)

		// Guard: 시계 역행 또는 다른 머신에서 복사된 파일로 인해
		// LastSeenUnix > nowUnix 인 경우, age 계산이 음수(int64 언더플로)가 되어
		// 만료된 세션이 복원되는 버그를 방지한다. gc.go와 동일한 패턴.
		if entry.LastSeenUnix > nowUnix {
			slog.Debug("Skipping session with future timestamp during restore",
				slog.Int64("last_seen_unix", entry.LastSeenUnix),
				slog.Int64("now_unix", nowUnix))
			continue
		}

		// Filter out expired sessions
		age := nowUnix - entry.LastSeenUnix
		var timeout time.Duration
		switch entry.Key.Protocol {
		case syscall.IPPROTO_TCP:
			timeout = tcpTimeout
		case syscall.IPPROTO_UDP:
			timeout = udpTimeout
		default:
			timeout = udpTimeout
		}

		if age > int64(timeout.Nanoseconds()) {
			continue
		}

		if entry.IsReverse {
			reverseKeys = append(reverseKeys, entry.Key)
			reverseValues = append(reverseValues, entry.Value)
		} else {
			conntrackKeys = append(conntrackKeys, entry.Key)
			conntrackValues = append(conntrackValues, entry.Value)
		}
	}

	// Load sessions into eBPF maps using chunked batch updates
	batchUpdateSize := int(batchSize)
	if batchUpdateSize <= 0 {
		batchUpdateSize = 1000
	}

	if len(conntrackKeys) > 0 {
		for i := 0; i < len(conntrackKeys); i += batchUpdateSize {
			end := min(i+batchUpdateSize, len(conntrackKeys))

			chunkKeys := conntrackKeys[i:end]
			chunkValues := conntrackValues[i:end]

			if n, err := m.objects.ConntrackMap.BatchUpdate(chunkKeys, chunkValues, nil); err != nil {
				slog.Warn("BatchUpdate conntrack_map partially failed",
					slog.Int("offset", i),
					slog.Int("updated_in_chunk", n),
					slog.Int("chunk_total", len(chunkKeys)),
					slog.Any("error", err))
				atomic.AddUint64(&m.restorationFailures, uint64(len(chunkKeys)-n))
			}
		}
	}

	if len(reverseKeys) > 0 {
		for i := 0; i < len(reverseKeys); i += batchUpdateSize {
			end := min(i+batchUpdateSize, len(reverseKeys))

			chunkKeys := reverseKeys[i:end]
			chunkValues := reverseValues[i:end]

			if n, err := m.objects.ReverseNatMap.BatchUpdate(chunkKeys, chunkValues, nil); err != nil {
				slog.Warn("BatchUpdate reverse_nat_map partially failed",
					slog.Int("offset", i),
					slog.Int("updated_in_chunk", n),
					slog.Int("chunk_total", len(chunkKeys)),
					slog.Any("error", err))
				atomic.AddUint64(&m.restorationFailures, uint64(len(chunkKeys)-n))
			}
		}
	}

	totalRestored := len(conntrackKeys) + len(reverseKeys)
	totalEntries := len(snapshot.Entries)
	failures := atomic.LoadUint64(&m.restorationFailures)

	slog.Info("Successfully restored NAT sessions",
		slog.String("path", path),
		slog.Int("conntrack", len(conntrackKeys)),
		slog.Int("reverse", len(reverseKeys)),
		slog.Uint64("failures", failures))

	// 복원 실패율 임계값 검사
	if totalEntries > 0 && failures > 0 {
		failureRate := float64(failures) / float64(totalRestored+int(failures))
		threshold := m.restorationFailureThreshold
		if threshold < 0 {
			threshold = 0.5
		}
		if failureRate > threshold {
			return fmt.Errorf("session restoration failure rate %.1f%% exceeds threshold %.1f%%: %d failures out of %d entries",
				failureRate*100, threshold*100, failures, totalEntries)
		}
	}
	_ = totalRestored // suppress unused variable warning if no failures

	return nil
}

func (m *Manager) AddSNATRule(srcIP, dstIP net.IP, srcPort, dstPort uint16, protocol uint8, transIP net.IP, transPort uint16) error {
	if m.isStopping.Load() {
		return ErrManagerStopping
	}
	if transIP == nil || transIP.To4() == nil {
		return fmt.Errorf("invalid translation IP: %v", transIP)
	}
	// 특수 용도 주소는 번역 대상으로 부적절하다 (loopback, multicast, unspecified, broadcast, link-local)
	if err := validateTranslationIPForNAT(transIP); err != nil {
		return fmt.Errorf("invalid SNAT translation IP: %w", err)
	}
	// Non-nil IPs must be IPv4 — IPv6 would silently become 0.0.0.0 via ipToUint32
	if srcIP != nil && srcIP.To4() == nil {
		return fmt.Errorf("src IP must be IPv4: %v", srcIP)
	}
	if dstIP != nil && dstIP.To4() == nil {
		return fmt.Errorf("dst IP must be IPv4: %v", dstIP)
	}

	// Ports are stored in host byte order to match BPF's bpf_ntohs() usage
	key := bpf.NatNatKey{
		SrcIp:    ipToUint32(srcIP),
		DstIp:    ipToUint32(dstIP),
		SrcPort:  srcPort,
		DstPort:  dstPort,
		Protocol: protocol,
	}

	entry := bpf.NatNatEntry{
		TranslatedIp:   ipToUint32(transIP),
		TranslatedPort: transPort,
	}

	return m.objects.ConntrackMap.Update(key, entry, 0)
}

func (m *Manager) AddDNATRule(srcIP, dstIP net.IP, srcPort, dstPort uint16, protocol uint8, transIP net.IP, transPort uint16) error {
	if m.isStopping.Load() {
		return ErrManagerStopping
	}
	if transIP == nil || transIP.To4() == nil {
		return fmt.Errorf("invalid translation IP: %v", transIP)
	}
	// 특수 용도 주소는 번역 대상으로 부적절하다 (loopback, multicast, unspecified, broadcast, link-local)
	if err := validateTranslationIPForNAT(transIP); err != nil {
		return fmt.Errorf("invalid DNAT translation IP: %w", err)
	}
	// Non-nil IPs must be IPv4 — IPv6 would silently become 0.0.0.0 via ipToUint32
	if srcIP != nil && srcIP.To4() == nil {
		return fmt.Errorf("src IP must be IPv4: %v", srcIP)
	}
	if dstIP != nil && dstIP.To4() == nil {
		return fmt.Errorf("dst IP must be IPv4: %v", dstIP)
	}

	// Ports are stored in host byte order to match BPF's bpf_ntohs() usage
	key := bpf.NatNatKey{
		SrcIp:    ipToUint32(srcIP),
		DstIp:    ipToUint32(dstIP),
		SrcPort:  srcPort,
		DstPort:  dstPort,
		Protocol: protocol,
	}

	entry := bpf.NatNatEntry{
		TranslatedIp:   ipToUint32(transIP),
		TranslatedPort: transPort,
	}

	return m.objects.DnatRules.Update(key, entry, 0)
}

// loadHMACKey는 HMAC 서명에 사용할 키를 로드한다.
// 우선순위: 환경변수 EBPF_NAT_HMAC_KEY > 키 파일 > nil(HMAC 미사용)
// nil 반환 시 HMAC 검증 없이 동작한다 (신규 설치 등 하위 호환).
func (m *Manager) loadHMACKey() []byte {
	// 1. 환경변수에서 base64 디코딩 시도
	if envKey := os.Getenv("EBPF_NAT_HMAC_KEY"); envKey != "" {
		key, err := base64.StdEncoding.DecodeString(envKey)
		if err != nil {
			slog.Warn("Failed to decode EBPF_NAT_HMAC_KEY from base64", slog.Any("error", err))
		} else if len(key) > 0 {
			return key
		}
	}

	// 2. 키 파일에서 로드 시도
	if m.hmacKeyFile != "" {
		data, err := os.ReadFile(m.hmacKeyFile)
		if err == nil && len(data) > 0 {
			return data
		}
		if !os.IsNotExist(err) && err != nil {
			slog.Warn("Failed to read HMAC key file", slog.String("path", m.hmacKeyFile), slog.Any("error", err))
		}
	}

	return nil
}

// ensureHMACKey는 HMAC 키를 반환한다.
// 환경변수나 키 파일에서 로드에 실패하면 새 키를 생성하여 키 파일에 저장한다.
// 키 파일 디렉터리가 없으면 생성을 시도하되 실패 시 nil을 반환한다.
func (m *Manager) ensureHMACKey() []byte {
	// 기존 키 로드 시도
	if key := m.loadHMACKey(); key != nil {
		return key
	}

	// 새 32바이트 키 생성
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		slog.Warn("Failed to generate HMAC key", slog.Any("error", err))
		return nil
	}

	// 키 파일에 저장
	if m.hmacKeyFile != "" {
		dir := filepath.Dir(m.hmacKeyFile)
		if err := os.MkdirAll(dir, 0700); err != nil {
			slog.Warn("Failed to create HMAC key directory",
				slog.String("dir", dir), slog.Any("error", err))
			return nil
		}
		if err := os.WriteFile(m.hmacKeyFile, key, 0600); err != nil {
			slog.Warn("Failed to write HMAC key file",
				slog.String("path", m.hmacKeyFile), slog.Any("error", err))
			return nil
		}
		slog.Info("Generated and saved new HMAC key", slog.String("path", m.hmacKeyFile))
	}

	return key
}

// computeHMAC는 주어진 데이터에 대한 HMAC-SHA256을 계산한다.
func computeHMAC(key, data []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(data)
	return mac.Sum(nil)
}

// validateTranslationIPForNAT는 NAT 번역 대상 IP의 유효성을 검증한다.
// 루프백, 멀티캐스트, 미지정, 브로드캐스트, 링크-로컬 주소는 번역 대상으로 부적절하다.
// config.validateTranslationIP와 동일한 로직 (패키지 간 순환 의존성 방지를 위해 별도 정의).
func validateTranslationIPForNAT(ip net.IP) error {
	if ip.IsLoopback() {
		return fmt.Errorf("loopback address not allowed as translation target: %s", ip)
	}
	if ip.IsMulticast() {
		return fmt.Errorf("multicast address not allowed as translation target: %s", ip)
	}
	if ip.IsUnspecified() {
		return fmt.Errorf("unspecified address not allowed as translation target: %s", ip)
	}
	if ip.Equal(net.IPv4bcast) {
		return fmt.Errorf("broadcast address not allowed as translation target: %s", ip)
	}
	if ip.IsLinkLocalUnicast() {
		return fmt.Errorf("link-local address not allowed as translation target: %s", ip)
	}
	return nil
}

func parseProtocol(p string) uint8 {
	switch p {
	case "tcp", "TCP":
		return uint8(syscall.IPPROTO_TCP)
	case "udp", "UDP":
		return uint8(syscall.IPPROTO_UDP)
	default:
		return 0
	}
}

func ipToUint32(ip net.IP) uint32 {
	ip = ip.To4()
	if ip == nil {
		return 0
	}
	// BPF는 iph->saddr/daddr를 호스트 바이트 순서(x86에서 리틀엔디안)로 읽는다.
	// Go 측도 NativeEndian으로 변환해야 BPF의 external_ip 비교가 정확하다.
	// BigEndian을 쓰면 10.0.0.1이 1.0.0.10으로 역전된다.
	return binary.NativeEndian.Uint32(ip)
}

func (m *Manager) GetRestorationFailures() uint64 {
	return atomic.LoadUint64(&m.restorationFailures)
}
