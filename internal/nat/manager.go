package nat

import (
	"compress/gzip"
	"context"
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
	batchUpdateSize     uint32
	restorationFailures uint64
	mu                  sync.RWMutex
	isStopping      atomic.Bool
}

func NewManager(objs *bpf.NatObjects) *Manager {
	return &Manager{
		objects:         objs,
		tcpTimeout:      24 * time.Hour,
		udpTimeout:      5 * time.Minute,
		batchUpdateSize: 1000,
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
	m.mu.RUnlock()
	gc := NewGarbageCollector(m.objects, tcpTimeout, udpTimeout)

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

	// Phase 2: Write to file without lock (I/O bound, should not block other operations)
	tmpFile := path + ".tmp"
	f, err := os.OpenFile(tmpFile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("failed to create temporary file: %w", err)
	}
	defer os.Remove(tmpFile) // Remove if we fail

	gw := gzip.NewWriter(f)
	encoder := gob.NewEncoder(gw)
	if err := encoder.Encode(snapshot); err != nil {
		gw.Close()
		f.Close()
		return fmt.Errorf("failed to encode session snapshot: %w", err)
	}
	if err := gw.Close(); err != nil {
		f.Close()
		return fmt.Errorf("failed to close gzip writer: %w", err)
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

	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			slog.Info("No session file found, skipping restoration", slog.String("path", path))
			return nil
		}
		return fmt.Errorf("failed to open session file: %w", err)
	}
	defer f.Close()

	var snapshot SessionSnapshot
	gr, err := gzip.NewReader(f)
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
			end := i + batchUpdateSize
			if end > len(conntrackKeys) {
				end = len(conntrackKeys)
			}

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
			end := i + batchUpdateSize
			if end > len(reverseKeys) {
				end = len(reverseKeys)
			}

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

	slog.Info("Successfully restored NAT sessions",
		slog.String("path", path),
		slog.Int("conntrack", len(conntrackKeys)),
		slog.Int("reverse", len(reverseKeys)))

	return nil
}

func (m *Manager) AddSNATRule(srcIP, dstIP net.IP, srcPort, dstPort uint16, protocol uint8, transIP net.IP, transPort uint16) error {
	if m.isStopping.Load() {
		return ErrManagerStopping
	}
	if transIP == nil || transIP.To4() == nil {
		return fmt.Errorf("invalid translation IP: %v", transIP)
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
	return binary.NativeEndian.Uint32(ip)
}

func (m *Manager) GetRestorationFailures() uint64 {
	return atomic.LoadUint64(&m.restorationFailures)
}
