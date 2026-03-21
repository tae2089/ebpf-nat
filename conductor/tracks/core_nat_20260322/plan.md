# Implementation Plan: Build core TC-based NAT functionality with ebpf-go (core_nat_20260322)

이 계획은 TDD(Test-Driven Development) 원칙을 따르며, 각 단계의 마지막에는 검증 프로토콜이 포함됩니다.

## Phase 1: Project Setup & eBPF Scaffolding
- [x] Task: Initialize Go module and eBPF build pipeline (f827845)
    - [ ] `go mod init` 및 `ebpf-go` 종속성 추가
    - [ ] eBPF C 코드 컴파일을 위한 `Makefile` 작성
- [~] Task: Create basic eBPF TC program (Skeleton)
    - [ ] 패킷을 단순히 통과시키는(TC_ACT_OK) 최소한의 C 프로그램 작성
    - [ ] Go에서 프로그램을 로드하고 인터페이스에 부착하는 기본 코드 구현
- [ ] Task: Conductor - User Manual Verification 'Phase 1: Project Setup & eBPF Scaffolding' (Protocol in workflow.md)

## Phase 2: Connection Tracking & Basic SNAT
- [ ] Task: Implement SNAT eBPF Maps
    - [ ] 세션 상태를 저장할 eBPF Hash/LRU 맵 정의 (C & Go)
- [ ] Task: Implement SNAT Logic in C
    - [ ] IPv4 Source IP/Port 변환 및 체크섬 업데이트 로직 구현
- [ ] Task: Implement Connection Tracking in Go
    - [ ] 패킷 흐름에 따른 세션 맵 업데이트 및 관리 로직 구현
- [ ] Task: Write Tests for SNAT
    - [ ] 네트워크 네임스페이스를 활용한 가상 환경에서 SNAT 변환 검증 테스트 작성
- [ ] Task: Implement SNAT to Pass Tests
    - [ ] 위 테스트를 통과하도록 C 및 Go 코드 완성
- [ ] Task: Conductor - User Manual Verification 'Phase 2: Connection Tracking & Basic SNAT' (Protocol in workflow.md)

## Phase 3: DNAT & Configuration Support
- [ ] Task: Implement DNAT Logic in C
    - [ ] IPv4 Destination IP/Port 변환 및 포트 포워딩 로직 구현
- [ ] Task: Implement YAML Configuration Loader
    - [ ] `slog`와 `trace`를 사용한 안정적인 설정 로더 구현 (YAML 기반)
- [ ] Task: Write Tests for DNAT & Config
    - [ ] 설정 파일 기반의 포트 포워딩 동작 검증 테스트 작성
- [ ] Task: Implement DNAT & Config to Pass Tests
    - [ ] 위 테스트를 통과하도록 최종 구현 완료
- [ ] Task: Conductor - User Manual Verification 'Phase 3: DNAT & Configuration Support' (Protocol in workflow.md)
