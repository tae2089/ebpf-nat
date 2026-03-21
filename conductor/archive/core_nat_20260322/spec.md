# Track Specification: Build core TC-based NAT functionality with ebpf-go (core_nat_20260322)

## 1. Goal
리눅스 커널의 TC(Traffic Control) 계층에서 동작하는 기본적인 NAT(Network Address Translation) 핵심 기능을 구현합니다. `ebpf-go` 라이브러리를 사용하여 제어 평면을 구축하고, C 언어로 데이터 평면(eBPF 프로그램)을 작성합니다.

## 2. Scope
- **eBPF 데이터 평면 (C):**
  - TC Ingress/Egress 프로그램 구현.
  - IPv4 헤더의 Source/Destination IP 및 Port 변환 로직.
  - 체크섬(Checksum) 재계산 (IP/TCP/UDP).
- **Go 제어 평면 (Go):**
  - `ebpf-go`를 통한 eBPF 프로그램 로드 및 인터페이스(veth/eth0 등) 부착.
  - NAT 세션 상태를 저장할 eBPF 맵(Hash/LRU) 관리.
  - YAML 설정을 통한 기본 NAT 규칙 로드.
- **Connection Tracking:**
  - 5-tuple (Src IP, Dst IP, Src Port, Dst Port, Protocol) 기반의 세션 관리.

## 3. Technical Requirements
- **Language:** Go 1.21+, C (Clang/LLVM 15+)
- **Library:** `cilium/ebpf`
- **Environment:** Linux Kernel 5.15+ (TC BPF support)
- **Error Handling:** `slog`, `github.com/tae2089/trace`

## 4. Acceptance Criteria
- [ ] eBPF 프로그램이 지정된 네트워크 인터페이스의 TC 계층에 성공적으로 부착됨.
- [ ] 내부 네트워크에서 외부로 나가는 패킷의 Source IP가 게이트웨이 IP로 변환됨 (SNAT).
- [ ] 외부에서 들어오는 응답 패킷이 원래의 내부 호스트 IP로 올바르게 역변환됨.
- [ ] YAML 파일에 정의된 포트 포워딩 규칙에 따라 외부 패킷이 내부 서버로 전달됨 (DNAT).
- [ ] 모든 패킷 변환 후 TCP/UDP/IP 체크섬이 유효하여 패킷이 드롭되지 않음.
