package nat

import (
	"fmt"
	"net"
	"encoding/binary"

	"github.com/imtaebin/ebpf-nat/internal/bpf"
)

type Manager struct {
	objects *bpf.NatObjects
}

func NewManager(objs *bpf.NatObjects) *Manager {
	return &Manager{objects: objs}
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

	if err := m.objects.ConntrackMap.Update(key, entry, 0); err != nil {
		return fmt.Errorf("failed to update conntrack map: %w", err)
	}

	return nil
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
