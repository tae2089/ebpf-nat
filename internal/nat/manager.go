package nat

import (
	"context"
	"encoding/binary"
	"log/slog"
	"net"
	"syscall"
	"time"

	"github.com/imtaebin/ebpf-nat/internal/bpf"
	"github.com/imtaebin/ebpf-nat/internal/config"
	"github.com/imtaebin/ebpf-nat/internal/ipdetect"
)

type Manager struct {
	objects    *bpf.NatObjects
	ipDetector ipdetect.Detector
	privateIP  net.IP
}

func NewManager(objs *bpf.NatObjects) *Manager {
	return &Manager{objects: objs}
}

func (m *Manager) LoadConfig(cfg *config.Config) error {
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
	cfg := bpf.NatSnatConfig{
		ExternalIp: ipToUint32(externalIP),
	}
	slog.Info("Updating SNAT configuration", slog.String("external_ip", externalIP.String()))
	return m.objects.SnatConfigMap.Update(uint32(0), cfg, 0)
}

func (m *Manager) updatePublicIP(ctx context.Context) error {
	if m.ipDetector == nil {
		return nil
	}

	ip, err := m.ipDetector.GetPublicIP(ctx)
	if err != nil {
		return err
	}

	return m.SetSNATConfig(ip)
}

// RunBackgroundTasks starts periodic tasks like IP detection.
func (m *Manager) RunBackgroundTasks(ctx context.Context, interval time.Duration) {
	if m.ipDetector == nil {
		return
	}

	slog.Info("Starting background IP detection", slog.Duration("interval", interval))
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			slog.Info("Stopping background IP detection")
			return
		case <-ticker.C:
			slog.Debug("Triggering periodic public IP detection")
			if err := m.updatePublicIP(ctx); err != nil {
				slog.Error("Periodic public IP detection failed", slog.Any("error", err))
				// We don't overwrite with private IP here to avoid flapping 
				// if it was previously successful.
			}
		}
	}
}

func (m *Manager) AddSNATRule(srcIP, dstIP net.IP, srcPort, dstPort uint16, protocol uint8, transIP net.IP, transPort uint16) error {
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
