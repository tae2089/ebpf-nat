# Tech Stack: TC-based NAT with ebpf-go

## 1. Programming Languages & eBPF Interaction
- **Go (Control Plane):** `ebpf-go` 라이브러리를 사용하여 eBPF 프로그램을 로드하고 맵을 관리하며 컨트롤 플레인 기능을 수행합니다 (Go 1.25 고정 사용).
- **C (Data Plane):** 리눅스 커널의 TC 계층에서 실행될 eBPF 프로그램을 표준 C 언어로 작성하며, `Clang/LLVM`을 통해 컴파일합니다.

## 2. Frameworks & Libraries
- **Networking:** `cilium/ebpf` (ebpf-go) - Go 기반의 현대적인 eBPF 로더 및 관리 라이브러리.
- **Environment Detection:** AWS IMDSv2, GCP Metadata Server, 및 `icanhazip.com` 등 외부 API를 활용한 환경 감지 및 Public IP 탐지.
- **Active Session Management:** 유저스페이스 백그라운드 루틴을 통한 주기적인 eBPF 맵 스캔 및 타임아웃 기반 세션 정리(GC).
- **Error Handling:** 
  - **slog:** Go 표준 라이브러리의 구조화된 로깅 패키지.
  - **github.com/tae2089/trace:** 에러 트래킹 및 트레이싱을 위한 외부 라이브러리 활용.

## 3. Configuration & Storage
- **Format:** `YAML` - 사람이 읽기 쉬운 표준 설정 형식을 사용하여 NAT 규칙 및 인터페이스 설정을 관리합니다.
- **Storage:** eBPF 맵을 활용하여 커널 내에서 실시간 세션 정보 및 통계 데이터를 관리합니다.

## 4. Observability & Monitoring
- **Metrics Export:** `Prometheus` - 커널 레벨에서 수집된 패킷 처리 지표(패킷 수, 바이트 수, 드롭 횟수 등)를 외부에 노출합니다.
- **Logging:** 구조화된 로그(slog)를 통해 시스템 상태와 중요 이벤트를 투명하게 기록합니다.

## 5. Development & Testing
- **AI-Assisted Development:** `context7` - AI 에이전트가 `cilium/ebpf` 등 주요 라이브러리의 최신 문서를 실시간으로 조회하고 참조하기 위한 스킬 활용.
- **Toolchain:** `Go Toolchain` (go build, go test) - 표준 Go 개발 도구 활용.
- **Automation:** `Makefile` 또는 `Magefile` - 빌드, 테스트, 배포 파이프라인 자동화 (Dockerized BPF compilation 포함).
- **Testbed:** `Containerized Networking Testbed` - Docker 또는 네트워크 네임스페이스를 활용한 가상 네트워크 환경에서의 기능 및 성능 테스트 수행.
