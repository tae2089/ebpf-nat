# Design: Session Persistence for eBPF NAT

## 1. 개요 (Overview)
본 설계는 `ebpf-nat` 서비스가 재시작되거나 시스템이 리부팅되더라도 기존의 활성 네트워크 세션(Connection Tracking) 정보를 유지하여 통신이 끊기지 않도록 하는 **세션 영속성(Persistence)** 기능을 정의합니다.

## 2. 목표 (Goals)
*   서비스 종료(`SIGTERM`, `SIGINT`) 시 현재 eBPF 맵의 세션 정보를 안전하게 저장합니다.
*   서비스 시작 시 저장된 세션을 복원하고, 시스템 리부팅 후에도 정확한 세션 만료 시간(`last_seen`)을 보정합니다.
*   대량의 세션(최대 64k)을 빠르게 처리하기 위해 효율적인 바이너리 포맷(`encoding/gob`)을 사용합니다.
*   원자적(Atomic) 파일 쓰기를 통해 데이터 무결성을 보장합니다.

## 3. 아키텍처 및 데이터 흐름 (Architecture)

### 3.1 저장 프로세스 (Save Process)
1.  종료 신호 감지 시 `Manager.SaveSessions()` 호출.
2.  `conntrack_map` 및 `reverse_nat_map` 전체 순회.
3.  `last_seen` (ktime) -> `Unix Nanoseconds` (Wall-clock) 변환.
    *   `last_seen_unix = (time.Now().UnixNano() - ktime_now) + last_seen_ktime`
4.  임시 파일(`.tmp`)에 `encoding/gob` 형식으로 쓰기.
5.  쓰기 완료 후 `os.Rename`으로 실제 저장 파일 교체.

### 3.2 복원 프로세스 (Restore Process)
1.  서비스 시작 시 `Manager.RestoreSessions()` 호출.
2.  파일 헤더의 버전 및 메타데이터 검증.
3.  시스템 부팅 시각(`boot_time_unix`) 계산.
    *   `boot_time_unix = time.Now().UnixNano() - ktime_now`
4.  저장된 `Unix Nanoseconds`를 새로운 `ktime`으로 역변환.
    *   `new_last_seen_ktime = saved_unix_nano - boot_time_unix`
5.  만료된 세션은 제외하고 eBPF 맵에 로드.

## 4. 데이터 구조 (Data Structures)

```go
type SessionSnapshot struct {
	Version   int
	CreatedAt time.Time
	Entries   []PersistentEntry
}

type PersistentEntry struct {
	Key          bpf.NatNatKey
	Value        bpf.NatNatEntry
	IsReverse    bool
	LastSeenUnix int64 // Unix Nanoseconds
}
```

## 5. 예외 처리 및 무결성 (Error Handling)
*   **파일 손상**: 파일 읽기 중 오류 발생 시 에러 로그를 남기고 깨끗한 상태(빈 맵)로 시작합니다.
*   **버전 불일치**: 바이너리 포맷 버전이 다를 경우 호환되지 않는 것으로 간주하고 로드하지 않습니다.
*   **시계 변동 (Clock Drift)**: 시스템 시계가 크게 변동한 경우, 세션이 너무 일찍 만료되거나 너무 오래 유지될 수 있으나 이는 다음 GC 사이클에서 보정됩니다.

## 6. 테스트 계획 (Testing)
1.  **Unit Tests**: 시간 변환 로직(`ktime` <-> `Unix`)의 정확성 검증.
2.  **Mock Tests**: eBPF 맵 없이 직렬화/역직렬화 전체 흐름 테스트.
3.  **Integration Tests**: 실제 트래픽 발생 후 재시작 시 세션 유지 여부 확인.
4.  **Reboot Simulation**: 부팅 시각 오프셋을 강제로 변경하여 시간 보정 로직 검증.
