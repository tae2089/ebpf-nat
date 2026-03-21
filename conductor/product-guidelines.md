# Product Guidelines: TC-based NAT with ebpf-go

## 1. Documentation & Prose Style
이 프로젝트의 문서는 **Educational & Friendly (교육적이고 친절한)** 스타일을 지향합니다.
- **친절한 설명:** 복잡한 eBPF 커널 동작이나 네트워크 변환 로직을 설명할 때 튜토리얼처럼 단계적으로 친절하게 안내합니다.
- **교육적 관점:** 코드를 읽는 것만으로도 eBPF 맵 구조나 TC 프로그램의 흐름을 이해할 수 있도록 상세한 주석과 문서를 제공합니다.

## 2. Technical Focus
개발 시 다음 세 가지 기술적 핵심 가치를 최우선으로 고려합니다.
- **Performance & Internals:** TC 계층에서 패킷이 처리되는 내부 메커니즘을 명확히 정의하고, 오버헤드를 최소화하는 최적화 기법을 적용합니다.
- **Stability & Reliability:** 네트워크 환경에서의 예외 상황(잘못된 패킷, 맵 가득 참 등)에 대한 강력한 에러 핸들링과 테스트 가능성을 보장합니다.
- **System Integration (Go-eBPF):** Go의 제어 평면과 eBPF의 데이터 평면 사이의 맵 구조와 통신 인터페이스를 효율적이고 직관적으로 설계합니다.

## 3. UX & Interface Principles
사용자(네트워크 관리자)에게 다음과 같은 운영 환경을 제공합니다.
- **Real-time Observability:** CLI와 로그를 통해 현재 NAT 세션 상태와 패킷 처리 통계 데이터를 실시간으로 투명하게 제공합니다.
- **Ease of Configuration:** YAML 또는 TOML과 같은 표준 설정 파일을 사용하여 누구나 쉽고 직관적으로 NAT 규칙을 정의할 수 있도록 합니다.
- **Actionable Diagnostics:** 문제 발생 시 명확한 에러 메시지와 상세한 디버그 모드를 제공하여 관리자가 신속하게 원인을 파악하고 조치할 수 있도록 돕습니다.
