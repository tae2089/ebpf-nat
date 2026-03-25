//go:build linux
// +build linux

package metrics

import (
	"encoding/binary"
	"syscall"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/tae2089/ebpf-nat/internal/bpf"
)

func TestNewScraper(t *testing.T) {
	reg := prometheus.NewRegistry()
	objs := &bpf.NatObjects{}
	scraper := NewScraper(objs, nil, reg)

	if scraper == nil {
		t.Fatal("NewScraper returned nil")
	}

	// Registration happens in NewScraper if reg is not nil.
	// If it reached here without panic, it's registered (MustRegister panics on error).
}

// TestCountMapEntries_PartialResultOnError: 항목 6
// countMapEntries가 이터레이션 중 에러 발생 시 0 대신 부분 카운트를 반환해야 한다.
// 정상 동작 케이스: 에러 없이 정확한 카운트를 반환한다.
func TestCountMapEntries_NormalCount(t *testing.T) {
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatal(err)
	}

	// NatNatKey/NatNatEntry 크기로 테스트 맵 생성
	keySize := uint32(binary.Size(bpf.NatNatKey{}))
	valueSize := uint32(binary.Size(bpf.NatNatEntry{}))

	m, err := ebpf.NewMap(&ebpf.MapSpec{
		Type:       ebpf.Hash,
		KeySize:    keySize,
		ValueSize:  valueSize,
		MaxEntries: 10,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()

	// 3개 엔트리 삽입
	for i := 0; i < 3; i++ {
		key := make([]byte, keySize)
		binary.NativeEndian.PutUint32(key, uint32(i+1))
		key[8] = syscall.IPPROTO_UDP // protocol 필드

		value := make([]byte, valueSize)
		if err := m.Put(key, value); err != nil {
			t.Fatalf("Put failed: %v", err)
		}
	}

	count := countMapEntries(m)
	if count != 3 {
		t.Errorf("countMapEntries = %d, want 3", count)
	}
}

// TestCountMapEntries_NilMap: nil 맵에 대해 0 반환해야 한다.
func TestCountMapEntries_NilMap(t *testing.T) {
	count := countMapEntries(nil)
	if count != 0 {
		t.Errorf("countMapEntries(nil) = %d, want 0", count)
	}
}
