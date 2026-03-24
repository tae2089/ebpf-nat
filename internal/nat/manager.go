package nat

import (
	"context"
	"encoding/binary"
	"encoding/gob"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"sync"
	"syscall"
	"time"

	"github.com/tae2089/ebpf-nat/internal/bpf"
	"github.com/tae2089/ebpf-nat/internal/config"
	"github.com/tae2089/ebpf-nat/internal/ipdetect"
)

var (
	ErrManagerStopping = errors.New("manager is stopping")
)

type Manager struct {
	objects    *bpf.NatObjects
	ipDetector ipdetect.Detector
	privateIP  net.IP
	tcpTimeout time.Duration
	udpTimeout time.Duration
	mu         sync.RWMutex
	isStopping bool
}

func NewManager(objs *bpf.NatObjects) *Manager {
	return &Manager{
		objects:    objs,
		tcpTimeout: 24 * time.Hour,
		udpTimeout: 5 * time.Minute,
	}
}

// Shutdown marks the manager as stopping.
func (m *Manager) Shutdown() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.isStopping = true
}

func (m *Manager) LoadConfig(cfg *config.Config) error {
	m.mu.Lock()
	if m.isStopping {
		m.mu.Unlock()
		return ErrManagerStopping
	}
	m.mu.Unlock()
	// Parse timeouts
	m.tcpTimeout = 24 * time.Hour
	if cfg.TCPTimeout != "" {
		if d, err := time.ParseDuration(cfg.TCPTimeout); err == nil {
			m.tcpTimeout = d
		}
	}
	m.udpTimeout = 5 * time.Minute
	if cfg.UDPTimeout != "" {
		if d, err := time.ParseDuration(cfg.UDPTimeout); err == nil {
			m.udpTimeout = d
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
			if err := m.SetSNATConfig(net.ParseIP(cfg.ExternalIP)); err != nil {
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

			// Initial detection
			if err := m.updatePublicIP(context.Background()); err != nil {
				slog.Error("Initial public IP detection failed, using private IP", slog.Any("error", err))
				if m.privateIP != nil {
					m.SetSNATConfig(m.privateIP)
				}
			}
		}
	}

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

func (m *Manager) SetSNATConfig(externalIP net.IP) error {
	m.mu.RLock()
	if m.isStopping {
		m.mu.RUnlock()
		return ErrManagerStopping
	}
	m.mu.RUnlock()

	cfg := bpf.NatSnatConfig{
		ExternalIp: ipToUint32(externalIP),
	}
	slog.Info("Updating SNAT configuration", slog.String("external_ip", externalIP.String()))
	return m.objects.SnatConfigMap.Update(uint32(0), cfg, 0)
}

func (m *Manager) updatePublicIP(ctx context.Context) error {
	m.mu.RLock()
	if m.isStopping {
		m.mu.RUnlock()
		return ErrManagerStopping
	}
	m.mu.RUnlock()

	if m.ipDetector == nil {
		return nil
	}

	ip, err := m.ipDetector.GetPublicIP(ctx)
	if err != nil {
		return err
	}

	return m.SetSNATConfig(ip)
}

// RunBackgroundTasks starts periodic tasks like IP detection and garbage collection.
func (m *Manager) RunBackgroundTasks(ctx context.Context, ipDetectInterval, gcInterval, tcpTimeout, udpTimeout time.Duration) {
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

	gc := NewGarbageCollector(m.objects, tcpTimeout, udpTimeout)

	for {
		select {
		case <-ctx.Done():
			slog.Info("Stopping background tasks")
			return
		case <-ipTickerC:
			m.mu.RLock()
			stopping := m.isStopping
			m.mu.RUnlock()
			if stopping {
				return
			}
			slog.Debug("Triggering periodic public IP detection")
			if err := m.updatePublicIP(ctx); err != nil {
				slog.Error("Periodic public IP detection failed", slog.Any("error", err))
			}
		case <-gcTicker.C:
			m.mu.RLock()
			stopping := m.isStopping
			m.mu.RUnlock()
			if stopping {
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
	// We allow SaveSessions during shutdown
	bootTime := getBootTimeUnixNano()
	snapshot := SessionSnapshot{
		Version:   1,
		CreatedAt: time.Now(),
		Entries:   []PersistentEntry{},
	}

	// Iterate ConntrackMap
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
		return fmt.Errorf("error iterating conntrack_map: %w", err)
	}

	// Iterate ReverseNatMap
	iter = m.objects.ReverseNatMap.Iterate()
	for iter.Next(&key, &entry) {
		snapshot.Entries = append(snapshot.Entries, PersistentEntry{
			Key:          key,
			Value:        entry,
			IsReverse:    true,
			LastSeenUnix: ktimeToUnix(entry.LastSeen, bootTime),
		})
	}
	if err := iter.Err(); err != nil {
		return fmt.Errorf("error iterating reverse_nat_map: %w", err)
	}

	// Create a temporary file for atomic write
	tmpFile := path + ".tmp"
	f, err := os.Create(tmpFile)
	if err != nil {
		return fmt.Errorf("failed to create temporary file: %w", err)
	}
	defer os.Remove(tmpFile) // Remove if we fail

	// Serialize using gob
	encoder := gob.NewEncoder(f)
	if err := encoder.Encode(snapshot); err != nil {
		f.Close()
		return fmt.Errorf("failed to encode session snapshot: %w", err)
	}

	// Ensure all data is written to disk
	if err := f.Sync(); err != nil {
		f.Close()
		return fmt.Errorf("failed to sync temporary file: %w", err)
	}
	f.Close()

	// Atomically rename
	if err := os.Rename(tmpFile, path); err != nil {
		return fmt.Errorf("failed to rename session file: %w", err)
	}

	slog.Info("Successfully saved NAT sessions", slog.String("path", path), slog.Int("entries", len(snapshot.Entries)))
	return nil
}

// RestoreSessions reads the session snapshot from a file and loads it into eBPF maps.
func (m *Manager) RestoreSessions(path string) error {
	m.mu.RLock()
	if m.isStopping {
		m.mu.RUnlock()
		return ErrManagerStopping
	}
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
	decoder := gob.NewDecoder(f)
	if err := decoder.Decode(&snapshot); err != nil {
		return fmt.Errorf("failed to decode session snapshot: %w", err)
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
			timeout = m.tcpTimeout
		case syscall.IPPROTO_UDP:
			timeout = m.udpTimeout
		default:
			timeout = m.udpTimeout
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
	const batchUpdateSize = 1000

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
	m.mu.RLock()
	if m.isStopping {
		m.mu.RUnlock()
		return ErrManagerStopping
	}
	m.mu.RUnlock()

	key := bpf.NatNatKey{
		SrcIp:    ipToUint32(srcIP),
		DstIp:    ipToUint32(dstIP),
		SrcPort:  htons(srcPort),
		DstPort:  htons(dstPort),
		Protocol: protocol,
	}

	entry := bpf.NatNatEntry{
		TranslatedIp:   ipToUint32(transIP),
		TranslatedPort: htons(transPort),
	}

	return m.objects.ConntrackMap.Update(key, entry, 0)
}

func (m *Manager) AddDNATRule(srcIP, dstIP net.IP, srcPort, dstPort uint16, protocol uint8, transIP net.IP, transPort uint16) error {
	m.mu.RLock()
	if m.isStopping {
		m.mu.RUnlock()
		return ErrManagerStopping
	}
	m.mu.RUnlock()

	key := bpf.NatNatKey{
		SrcIp:    ipToUint32(srcIP),
		DstIp:    ipToUint32(dstIP),
		SrcPort:  htons(srcPort),
		DstPort:  htons(dstPort),
		Protocol: protocol,
	}

	entry := bpf.NatNatEntry{
		TranslatedIp:   ipToUint32(transIP),
		TranslatedPort: htons(transPort),
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
	return binary.LittleEndian.Uint32(ip)
}

func htons(i uint16) uint16 {
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, i)
	return binary.LittleEndian.Uint16(b)
}
