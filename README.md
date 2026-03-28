# ebpf-nat

[![CI](https://github.com/imtaebin/ebpf-nat/actions/workflows/ci.yml/badge.svg)](https://github.com/imtaebin/ebpf-nat/actions/workflows/ci.yml)
[![Release](https://github.com/imtaebin/ebpf-nat/actions/workflows/release.yml/badge.svg)](https://github.com/imtaebin/ebpf-nat/actions/workflows/release.yml)

**ebpf-nat**은 리눅스 커널의 **TC(Traffic Control)** 지점에서 동작하는 고성능 eBPF 기반 NAT(Network Address Translation) 솔루션입니다. Go 언어(`ebpf-go`)를 컨트롤 플레인으로 활용하여 강력한 성능과 유연한 관리 기능을 동시에 제공합니다.

## 핵심 기능 (Key Features)

- **🚀 고성능 패킷 처리 (TC-based)**: 커널 네트워크 스택의 초기 단계인 TC에서 패킷을 직접 변환하여 지연 시간을 최소화하고 처리량을 극대화합니다.
- **🔄 Dynamic SNAT (Masquerading)**: 내부 네트워크 기기들이 하나의 외부 IP를 공유하여 인터넷에 접속할 수 있도록 포트를 동적으로 할당하고 관리합니다.
- **🎯 Static DNAT (Port Forwarding)**: 외부 포트를 특정 내부 IP/포트로 전달하는 포트 포워딩 기능을 지원합니다.
- **💾 세션 영속성 (Session Persistence)**: 서비스 재시작이나 시스템 리부팅 시에도 활성 세션 정보를 유지하여 기존 연결(SSH, TCP 등)이 끊기지 않도록 보장합니다.
- **📡 자동 공인 IP 감지**: AWS, GCP 등 클라우드 환경이나 일반 네트워크에서 외부 IP를 자동으로 감지하여 Masquerading을 수행합니다.
- **🛠 Full ICMP 지원**: ICMP Echo(Ping)뿐만 아니라 Path MTU Discovery를 위한 ICMP Error 메시지 변환을 완벽하게 지원합니다.
- **📊 실시간 모니터링**: Prometheus 포맷의 메트릭을 통해 패킷 처리량, 세션 수, 포트 할당 상태 등을 실시간으로 추적할 수 있습니다.
- **🧹 스마트 세션 관리**: 유저스페이스 GC(Garbage Collector)가 비활성 세션을 자동으로 감지하고 제거하여 시스템 안정성을 유지합니다.
- **🔒 Anti-Spoofing**: 내부 서브넷 외부의 소스 IP를 가진 패킷을 커널 레벨에서 차단하여 IP 스푸핑 공격을 방어합니다.
- **🔑 메트릭 인증**: Bearer 토큰 기반 인증으로 Prometheus 메트릭 엔드포인트를 보호합니다.

## 아키텍처 (Architecture)

```text
[ Internal Network ] <---> [ ebpf-nat (TC Ingress/Egress) ] <---> [ External Internet ]
                                     |
                          [ Go Control Plane (Manager) ]
                                     |
                          [ eBPF Maps (Conntrack/DNAT) ]
```

- **Data Plane**: C로 작성된 eBPF 프로그램이 커널 내에서 실제 패킷 헤더(IP, Port, Checksum)를 변환합니다.
- **Control Plane**: Go로 작성된 매니저가 eBPF 맵을 관리하고, 세션을 추적하며, 설정을 동적으로 적용합니다.

## 설치 및 실행 (Installation & Usage)

### 사전 요구 사항
- Linux Kernel 5.4 이상 (BTF 지원 권장)
- Go 1.25 이상
- LLVM/Clang (eBPF 컴파일용)
- `libbpf-dev` 및 커널 헤더

### 빌드 및 설치
```bash
# 바이너리 빌드 (Docker 기반 빌더 사용)
make build

# 시스템 설치 (바이너리, Systemd 서비스 등록)
sudo ./scripts/install.sh
```

### 실행
1. `/etc/default/ebpf-nat` 파일에서 네트워크 인터페이스를 설정합니다.
   ```bash
   EBPF_NAT_INTERFACE=eth0
   ```
2. 서비스를 시작합니다.
   ```bash
   sudo systemctl start ebpf-nat
   ```

## 설정 (Configuration)

설정 파일(`config.yaml`) 또는 CLI 플래그를 통해 동작을 제어할 수 있습니다.

| 플래그 | 설명 | 기본값 |
|--------|------|--------|
| `--interface`, `-i` | eBPF를 적용할 네트워크 인터페이스 | (필수) |
| `--masquerade` | 동적 SNAT (IP 마스커레이딩) 활성화 | `true` |
| `--external-ip` | SNAT에 사용할 고정 외부 IP (설정 시 자동 감지 무시) | `""` |
| `--internal-net` | Anti-Spoofing용 내부 서브넷 CIDR (예: `192.168.1.0/24`) | `""` |
| `--ip-detect-type` | 외부 IP 감지 방식 (`aws`, `gcp`, `generic`, `auto`) | `auto` |
| `--ip-detect-interval` | 외부 IP 재감지 주기 | `5m` |
| `--max-sessions` | 최대 NAT 세션 수 | `65536` |
| `--max-sessions-per-source` | 소스 IP당 최대 세션 수 (0은 비활성화) | `0` |
| `--gc-interval` | 만료 세션 정리 주기 | `1m` |
| `--tcp-timeout` | TCP 세션 만료 시간 | `24h` |
| `--udp-timeout` | UDP 세션 만료 시간 | `5m` |
| `--max-mss` | TCP MSS Clamping 값 (0은 비활성화) | `0` |
| `--session-file` | 세션 정보를 저장/복원할 경로 | `/var/lib/ebpf-nat/sessions.gob` |
| `--batch-update-size` | 세션 복원 시 일괄 업데이트 크기 | `1000` |
| `--restoration-failure-threshold` | 세션 복원 허용 실패율 (0.0~1.0) | `0.5` |
| `--metrics-enabled` | Prometheus 메트릭 활성화 | `false` |
| `--metrics-address` | 메트릭 서버 바인드 주소 | `127.0.0.1` |
| `--metrics-port` | 메트릭 서버 포트 | `9090` |
| `--metrics-bearer-token` | 메트릭 엔드포인트 Bearer 토큰 인증 (`EBPF_NAT_METRICS_TOKEN` 환경변수로도 설정 가능) | `""` |
| `--debug`, `-d` | 디버그 로깅 및 BPF 트레이싱 활성화 | `false` |

## 개발 및 테스트 (Development)

### 테스트 실행
네트워크 네임스페이스를 활용한 블랙박스 통합 테스트를 포함한 모든 테스트를 실행합니다.
```bash
make test
```

### 개별 통합 테스트
```bash
make integration-test
```

### Python 블랙박스 테스트
실제 `ebpf-nat` 바이너리를 대상으로 네트워크 네임스페이스 환경에서 엔드투엔드 검증을 수행합니다.
```bash
make python-test
```

| 테스트 케이스 | 검증 내용 |
|---|---|
| TC-01 TCP SNAT | TCP 연결 시 소스 IP가 외부 GW로 마스커레이딩되는지 확인 |
| TC-02 UDP SNAT | UDP 전송 시 소스 IP 마스커레이딩 확인 |
| TC-03 ICMP Ping | NAT를 통한 ping 통과 여부 |
| TC-04 Large TCP (1MB) | 대용량 TCP 데이터 무결성 및 체크섬 |
| TC-05 Bidirectional TCP | 서버 echo-back 정상 동작 |
| TC-06 Concurrent TCP (10) | 동시 10개 연결의 SNAT 처리 |
| TC-07 Rapid Reconnect (20x) | 빠른 연결/해제 후 세션 테이블 무결성 |
| TC-08 Anti-Spoofing | 내부 서브넷 외 소스 IP 패킷 차단 확인 |
| TC-09 UDP Multiple Flows (5) | 동시 5개 UDP 클라이언트 SNAT |
| TC-10 Session Persistence | 재시작 후 세션 파일 저장/복원 |

## 라이선스 (License)
이 프로젝트는 **GPL-2.0** 라이선스 하에 배포됩니다.
