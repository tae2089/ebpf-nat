package nat

import (
	"net"
	"encoding/binary"
	"syscall"

	"github.com/imtaebin/ebpf-nat/internal/bpf"
	"github.com/imtaebin/ebpf-nat/internal/config"
)

type Manager struct {
	objects *bpf.NatObjects
}

func NewManager(objs *bpf.NatObjects) *Manager {
	return &Manager{objects: objs}
}

func (m *Manager) LoadConfig(cfg *config.Config) error {
	if cfg.Masquerade {
		var externalIP net.IP
		if cfg.ExternalIP != "" {
			externalIP = net.ParseIP(cfg.ExternalIP)
		} else {
			// Find IP of the interface
			iface, err := net.InterfaceByName(cfg.Interface)
			if err == nil {
				addrs, err := iface.Addrs()
				if err == nil {
					for _, addr := range addrs {
						if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
							if ip4 := ipnet.IP.To4(); ip4 != nil {
								externalIP = ip4
								break
							}
						}
					}
				}
			}
		}
		if externalIP != nil {
			if err := m.SetSNATConfig(externalIP); err != nil {
				return err
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
	return m.objects.SnatConfigMap.Update(uint32(0), cfg, 0)
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
