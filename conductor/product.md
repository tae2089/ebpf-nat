# Initial Concept

ebpf-go를 통해 tc 기반의 nat 솔루션 개발

---

# Product Guide: TC-based NAT with ebpf-go

## 1. Vision & Overview
이 프로젝트는 Go 언어의 `ebpf-go` 라이브러리를 활용하여 리눅스 커널의 **TC(Traffic Control)** 지점에서 동작하는 고성능 NAT(Network Address Translation) 솔루션을 개발하는 것을 목표로 합니다. 성능과 유지보수성을 동시에 잡는 현대적인 네트워크 유틸리티를 지향합니다.

## 2. Target Audience
- **Edge/Home Router Admin:** 저사양 또는 전용 임베디드 장비에서 효율적인 패킷 변환을 필요로 하는 사용자.
- **Network Engineer / Learning:** eBPF 기반의 패킷 처리를 실무적으로 적용하거나 학습하고자 하는 엔지니어.

## 3. Core Goals
- **High Performance (TC-based):** 커널 스택 깊숙한 곳(TC)에서 패킷을 처리하여 최소 지연 시간과 최대 처리량을 보장합니다.
- **Maintainability (Go-centric):** Go 언어를 컨트롤 플레인으로 활용하여 eBPF 맵 관리, 설정 및 모니터링을 직관적이고 안정적으로 수행합니다.
- **Observability & Flexibility:** eBPF의 강력한 맵 구조를 통해 실시간 세션 정보와 통계 데이터를 추적하며, 필요에 따라 유연하게 기능을 확장할 수 있습니다.

## 4. Key Features
- **SNAT (Source NAT):** 내부 네트워크 기기들이 하나의 외부 IP를 공유하여 외부로 나갈 수 있게 하는 주소 변환(Masquerading 포함).
- **Automatic Public IP Detection:** AWS, GCP 등 클라우드 환경이나 일반 네트워크에서 외부로 나가는 Public IP를 자동으로 감지하여 별도의 설정 없이 Masquerading을 수행합니다.
- **DNAT (Destination NAT):** 외부로부터 들어오는 트래픽을 특정 내부 IP/포트로 전달하는 기능(포트 포워딩).
- **Connection Tracking & Active Aging:** eBPF 맵을 통한 실시간 세션 추적뿐만 아니라, 유저스페이스의 Garbage Collector가 비활성 세션을 자동으로 감지하고 제거하여 시스템 안정성을 보장합니다.

## 5. Primary Use Case
- **SOHO Gateway Service:** 소규모 사무실이나 가정용 게이트웨이 서비스로 활용되어, 단순하면서도 강력한 네트워크 주소 변환 기능을 제공합니다.
