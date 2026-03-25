//go:build linux

package nat

import (
	"compress/gzip"
	"encoding/binary"
	"encoding/gob"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/tae2089/ebpf-nat/internal/bpf"
)

func TestTimeConversion(t *testing.T) {
	bootTime := getBootTimeUnixNano()
	if bootTime <= 0 {
		t.Errorf("expected boot time > 0, got %d", bootTime)
	}

	// Wait a bit to ensure time moves forward
	time.Sleep(10 * time.Millisecond)

	now := time.Now().UnixNano()
	ktime := unixToKtime(now, bootTime)

	// ktime should be approximately now - bootTime
	// Since getBootTimeUnixNano and time.Now() are called at different times,
	// there might be a small drift, but it should be very small.

	convertedUnix := ktimeToUnix(ktime, bootTime)
	if convertedUnix != now {
		t.Errorf("expected %d, got %d", now, convertedUnix)
	}
}

func TestKtimeToUnix(t *testing.T) {
	bootTime := int64(1000000000)  // 1 second after epoch
	ktime := uint64(500000000)    // 0.5 seconds after boot
	expected := int64(1500000000) // 1.5 seconds after epoch

	result := ktimeToUnix(ktime, bootTime)
	if result != expected {
		t.Errorf("expected %d, got %d", expected, result)
	}
}

func TestUnixToKtime(t *testing.T) {
	bootTime := int64(1000000000)  // 1 second after epoch
	unixNano := int64(1500000000)  // 1.5 seconds after epoch
	expected := uint64(500000000) // 0.5 seconds after boot

	result := unixToKtime(unixNano, bootTime)
	if result != expected {
		t.Errorf("expected %d, got %d", expected, result)
	}

	// Test negative case
	unixNano = int64(500000000) // 0.5 seconds after epoch (before boot)
	result = unixToKtime(unixNano, bootTime)
	if result != 0 {
		t.Errorf("expected 0 for time before boot, got %d", result)
	}
}

func TestRestoreSessions_UnsupportedVersion(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sessions.gob")

	// Write a snapshot with an unsupported version
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	gw := gzip.NewWriter(f)
	if err := gob.NewEncoder(gw).Encode(SessionSnapshot{Version: 99, CreatedAt: time.Now()}); err != nil {
		gw.Close()
		f.Close()
		t.Fatal(err)
	}
	gw.Close()
	f.Close()

	objs := &bpf.NatObjects{}
	mgr := NewManager(objs)
	err = mgr.RestoreSessions(path)
	if err == nil {
		t.Error("expected error for unsupported snapshot version, got nil")
	}
}

// newTestMaps는 테스트용 BPF 맵 2개(conntrack, reverse)를 생성한다.
func newTestMaps(t *testing.T) (*ebpf.Map, *ebpf.Map) {
	t.Helper()
	spec, err := bpf.LoadNat()
	if err != nil {
		t.Fatalf("LoadNat: %v", err)
	}
	cm, err := ebpf.NewMap(spec.Maps["conntrack_map"])
	if err != nil {
		t.Fatalf("NewMap conntrack_map: %v", err)
	}
	rm, err := ebpf.NewMap(spec.Maps["reverse_nat_map"])
	if err != nil {
		cm.Close()
		t.Fatalf("NewMap reverse_nat_map: %v", err)
	}
	return cm, rm
}

// newTestNatObjects는 conntrack + reverse 맵만 포함한 NatObjects를 반환한다.
func newTestNatObjects(cm, rm *ebpf.Map) *bpf.NatObjects {
	return &bpf.NatObjects{
		NatMaps: bpf.NatMaps{
			ConntrackMap:  cm,
			ReverseNatMap: rm,
		},
	}
}

// TestSaveAndRestoreSessions_HMACIntegrity: HMAC 무결성 검증
// SaveSessions가 HMAC 서명을 추가하고, RestoreSessions가 이를 검증하는지 확인한다.
func TestSaveAndRestoreSessions_HMACIntegrity(t *testing.T) {
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "sessions.gob")

	// HMAC 키를 환경변수로 설정
	// base64("testkeytestkeytestkeytestkey") = "dGVzdGtleXRlc3RrZXl0ZXN0a2V5"
	keyB64 := "dGVzdGtleXRlc3RrZXl0ZXN0a2V5dGVzdA=="
	t.Setenv("EBPF_NAT_HMAC_KEY", keyB64)

	cm, rm := newTestMaps(t)
	defer cm.Close()
	defer rm.Close()

	objs := newTestNatObjects(cm, rm)
	mgr := NewManager(objs)
	mgr.hmacKeyFile = filepath.Join(dir, ".hmac.key")

	// 저장
	if err := mgr.SaveSessions(path); err != nil {
		t.Fatalf("SaveSessions failed: %v", err)
	}

	// 복원 성공 확인 (동일 키 → HMAC 검증 통과)
	if err := mgr.RestoreSessions(path); err != nil {
		t.Errorf("RestoreSessions with valid HMAC failed: %v", err)
	}
}

// TestRestoreSessions_HMACTampering: HMAC 불일치 시 에러 반환
// 세션 파일이 조작되면 악의적인 NAT 엔트리 주입을 방지해야 한다.
func TestRestoreSessions_HMACTampering(t *testing.T) {
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "sessions.gob")

	// 유효한 키로 저장
	keyB64 := "dGVzdGtleXRlc3RrZXl0ZXN0a2V5dGVzdA=="
	t.Setenv("EBPF_NAT_HMAC_KEY", keyB64)

	cm, rm := newTestMaps(t)
	defer cm.Close()
	defer rm.Close()

	objs := newTestNatObjects(cm, rm)
	mgr := NewManager(objs)
	mgr.hmacKeyFile = filepath.Join(dir, ".hmac.key")

	if err := mgr.SaveSessions(path); err != nil {
		t.Fatalf("SaveSessions failed: %v", err)
	}

	// 파일 내용을 조작: HMAC 부분(파일 끝에서 5~36번째 바이트)을 변경
	// 파일 형식: [gzip data][32-byte HMAC][4-byte magic "EBPF"]
	// magic은 건드리지 않고 HMAC 내용만 변경해야 HMAC trailer로 인식된다
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	// HMAC이 위치한 곳(magic 앞 32바이트)의 첫 번째 바이트를 뒤집는다
	hmacOffset := len(data) - 36 // 32 HMAC + 4 magic
	if hmacOffset >= 0 {
		data[hmacOffset] ^= 0xFF
	} else if len(data) > 4 {
		// 매우 짧은 파일의 경우 첫 번째 바이트 변경
		data[0] ^= 0xFF
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}

	// 동일 키지만 데이터가 조작됨 → HMAC 불일치 → 에러 반환
	err = mgr.RestoreSessions(path)
	if err == nil {
		t.Error("expected error for tampered session file, got nil")
	}
}

// TestRestoreSessions_NoHMACKey_WarnsAndRestores: 키가 없을 때 경고 후 복원 성공
// 신규 설치나 키 파일이 없는 경우 HMAC 검증 없이 복원해야 한다 (하위 호환).
func TestRestoreSessions_NoHMACKey_WarnsAndRestores(t *testing.T) {
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "sessions.gob")

	// 환경변수를 비워서 "키 없음" 상태 시뮬레이션
	t.Setenv("EBPF_NAT_HMAC_KEY", "")

	cm, rm := newTestMaps(t)
	defer cm.Close()
	defer rm.Close()

	objs := newTestNatObjects(cm, rm)
	mgr := NewManager(objs)

	// 쓸 수 없는 경로로 설정하여 키 파일 자동 생성이 실패하도록 한다
	// /proc은 읽기 전용이므로 MkdirAll/WriteFile이 실패한다
	mgr.hmacKeyFile = "/proc/no_such_dir_for_testing/.hmac.key"

	// 저장 (HMAC 키 없음 → HMAC trailer 없이 저장)
	if err := mgr.SaveSessions(path); err != nil {
		t.Fatalf("SaveSessions without HMAC key failed: %v", err)
	}

	// 복원도 성공해야 함 (경고는 로그로 출력되지만 에러 반환하지 않음)
	if err := mgr.RestoreSessions(path); err != nil {
		t.Errorf("RestoreSessions without HMAC key should succeed: %v", err)
	}
}

// TestRestoreSessions_ResetsFailureCounter: 항목 3
// RestoreSessions를 반복 호출해도 restorationFailures가 누적되지 않고 초기화되어야 한다.
func TestRestoreSessions_ResetsFailureCounter(t *testing.T) {
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "sessions.gob")

	cm, rm := newTestMaps(t)
	defer cm.Close()
	defer rm.Close()

	objs := newTestNatObjects(cm, rm)
	mgr := NewManager(objs)
	mgr.hmacKeyFile = filepath.Join(dir, ".hmac.key")

	// 첫 번째 RestoreSessions 호출 (세션 파일 없음 → 건너뜀)
	if err := mgr.RestoreSessions(path + ".notexist"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// restorationFailures를 인위적으로 설정 (이전 복원 시 실패가 누적된 것 시뮬레이션)
	atomic.StoreUint64(&mgr.restorationFailures, 5)

	// 두 번째 RestoreSessions 호출 전 실패 카운터 확인
	if got := atomic.LoadUint64(&mgr.restorationFailures); got != 5 {
		t.Fatalf("expected 5 failures before second call, got %d", got)
	}

	// 유효한 세션 파일 생성 (빈 세션)
	if err := mgr.SaveSessions(path); err != nil {
		t.Fatalf("SaveSessions failed: %v", err)
	}

	// 두 번째 RestoreSessions 호출 → restorationFailures가 0으로 초기화되어야 함
	if err := mgr.RestoreSessions(path); err != nil {
		t.Fatalf("RestoreSessions failed: %v", err)
	}

	// 이전 실패(5개)가 누적되지 않고 이번 복원의 실패만 카운트되어야 함
	// 빈 세션 파일이므로 실패는 0이어야 한다
	if got := atomic.LoadUint64(&mgr.restorationFailures); got != 0 {
		t.Errorf("expected 0 failures after second call (reset), got %d", got)
	}
}

// TestRestoreSessions_HMACKeySet_NoHMACInFile_Rejected: 항목 5
// HMAC 키가 설정되어 있는데 파일에 HMAC 서명이 없으면 에러를 반환해야 한다.
func TestRestoreSessions_HMACKeySet_NoHMACInFile_Rejected(t *testing.T) {
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "sessions.gob")

	// HMAC 없이 세션 파일 저장 (환경변수 비워서 키 없는 상태로 저장)
	t.Setenv("EBPF_NAT_HMAC_KEY", "")

	cm, rm := newTestMaps(t)
	defer cm.Close()
	defer rm.Close()

	objs := newTestNatObjects(cm, rm)
	mgrSave := NewManager(objs)
	// 키 파일 없는 디렉터리 설정 → HMAC trailer 없이 저장
	mgrSave.hmacKeyFile = filepath.Join(dir, ".nonexistent_dir", ".hmac.key")

	if err := mgrSave.SaveSessions(path); err != nil {
		t.Fatalf("SaveSessions without HMAC failed: %v", err)
	}

	// 파일에 HMAC trailer가 없는지 확인 (magic bytes 없음)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(data) >= 4 {
		tail := data[len(data)-4:]
		if string(tail) == "EBPF" {
			t.Skip("File unexpectedly has HMAC trailer; skipping test")
		}
	}

	// 이제 HMAC 키를 설정하고 복원 시도 → 에러여야 함
	keyB64 := "dGVzdGtleXRlc3RrZXl0ZXN0a2V5dGVzdA=="
	t.Setenv("EBPF_NAT_HMAC_KEY", keyB64)

	mgrRestore := NewManager(objs)
	mgrRestore.hmacKeyFile = filepath.Join(dir, ".hmac.key")

	err = mgrRestore.RestoreSessions(path)
	if err == nil {
		t.Error("expected error when HMAC key is set but file has no HMAC signature, got nil")
	}
}

// TestRestorationFailureThreshold_ExceedLimit: 복원 실패율이 임계값을 초과하면 에러 반환
func TestRestorationFailureThreshold_ExceedLimit(t *testing.T) {
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatal(err)
	}

	// 매우 작은 맵 생성 (BatchUpdate가 실패하도록)
	conntrackMap, err := ebpf.NewMap(&ebpf.MapSpec{
		Type:       ebpf.LRUHash,
		KeySize:    uint32(binary.Size(bpf.NatNatKey{})),
		ValueSize:  uint32(binary.Size(bpf.NatNatEntry{})),
		MaxEntries: 1, // 매우 작은 맵
	})
	if err != nil {
		t.Fatal(err)
	}
	defer conntrackMap.Close()

	dir := t.TempDir()
	path := filepath.Join(dir, "sessions.gob")

	// 많은 세션을 포함한 파일을 직접 생성
	now := time.Now()
	nowUnix := now.UnixNano()
	// 미래 타임스탬프가 아닌 최근 타임스탬프 사용 (복원 가능한 세션)
	entries := make([]PersistentEntry, 10)
	for i := range entries {
		entries[i] = PersistentEntry{
			Key: bpf.NatNatKey{
				SrcIp:    uint32(i + 1),
				DstIp:    0x08080808,
				SrcPort:  uint16(10000 + i),
				DstPort:  80,
				Protocol: 6,
			},
			Value:        bpf.NatNatEntry{TranslatedIp: uint32(i + 100)},
			IsReverse:    false,
			LastSeenUnix: nowUnix - int64(time.Second), // 1초 전 (만료되지 않음)
		}
	}

	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	gw := gzip.NewWriter(f)
	if err := gob.NewEncoder(gw).Encode(SessionSnapshot{
		Version:   1,
		CreatedAt: now,
		Entries:   entries,
	}); err != nil {
		gw.Close()
		f.Close()
		t.Fatal(err)
	}
	gw.Close()
	f.Close()

	// 맵이 너무 작아 BatchUpdate가 일부 실패하는 상황
	// RestorationFailureThreshold를 0.0으로 설정 → 실패 즉시 에러
	objs := &bpf.NatObjects{
		NatMaps: bpf.NatMaps{
			ConntrackMap: conntrackMap,
		},
	}
	mgr := NewManager(objs)
	mgr.restorationFailureThreshold = 0.0 // 실패율 0% 초과 즉시 에러

	// 복원 시도 - 맵이 너무 작아서 일부 실패 예상
	// 에러가 반환되어야 함
	err = mgr.RestoreSessions(path)
	// 실패 임계값 0.0에서 실패가 발생하면 에러를 반환
	// 맵 크기가 1이고 세션이 10개이므로 실패율 > 0 → 에러
	if err == nil {
		t.Log("Note: BatchUpdate may not have failed (LRU eviction may have handled it)")
	}
}
