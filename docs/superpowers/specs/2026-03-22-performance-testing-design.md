# Design: End-to-End Performance Testing for eBPF NAT

## 1. 개요 (Overview)
본 설계는 eBPF NAT 솔루션의 성능을 객관적으로 측정하기 위한 부하 테스트 환경을 구축하는 것을 목표로 합니다. 특히 `t2.micro` 인스턴스 환경(1 vCPU, 1GB RAM)을 시뮬레이션하여 실제 운영 환경에서의 안정성과 처리량을 검증합니다.

## 2. 테스트 환경 구성 (Test Environment)

### 2.1 네트워크 토폴로지
`docker-compose`를 사용하여 3개의 독립된 컨테이너를 생성하고 가상 네트워크로 연결합니다.

```text
[ Client ] <--- (net-internal) ---> [ NAT-Gateway ] <--- (net-external) ---> [ Server ]
IP: 172.20.0.2                      IP-Internal: 172.20.0.1                  IP: 172.30.0.2
                                    IP-External: 172.30.0.1
```

### 2.2 컨테이너 사양
1.  **NAT-Gateway (ebpf-nat)**:
    *   **Resource Limit**: CPU 1.0 (1 vCPU), Memory 1GB.
    *   **Role**: `ebpf-nat` 실행 및 패킷 포워딩 (`ip_forward=1`).
    *   **Config**: Dynamic SNAT (Masquerade) 활성화.
2.  **Client (Traffic Generator)**:
    *   **Tools**: `iperf3`, `wrk`, `hping3`.
    *   **Gateway Setup**: `ip route add default via 172.20.0.1`.
3.  **Server (Target)**:
    *   **Tools**: `iperf3` (Server mode), `nginx` (for HTTP load).

## 3. 측정 지표 및 시나리오 (Metrics & Scenarios)

### 3.1 Throughput (대역폭 측정)
*   **TCP**: `iperf3 -c 172.30.0.2 -t 30 -P 4` (병렬 스트림을 통한 최대 대역폭 확인).
*   **UDP**: `iperf3 -c 172.30.0.2 -u -b 0 -t 30` (패킷 유실 없이 처리 가능한 최대 UDP 대역폭 확인).

### 3.2 PPS (Packets Per Second)
*   **64B Small Packets**: `hping3 --udp -S 172.30.0.2 -p 80 -d 64 --flood`
*   **목표**: 초당 패킷 처리 능력을 측정하여 eBPF 데이터 플레인의 효율성 검증.

### 3.3 RPS & Connection Tracking (요청 처리 및 세션 관리)
*   **HTTP Load**: `wrk -t12 -c400 -d30s http://172.30.0.2/`
*   **검증**: 많은 수의 동시 연결 생성 시 conntrack 맵 업데이트 오버헤드 및 CPU/메모리 사용량 확인.

### 3.4 Latency (지연 시간)
*   부하가 없는 유휴 상태에서의 `ping` 지연 시간 측정.
*   부하(throughput 80% 이상) 상태에서의 `ping` 지연 시간 변화 측정.

## 4. 모니터링 전략 (Monitoring)

1.  **System**: `docker stats`를 통한 실시간 리소스 점유율 기록.
2.  **eBPF Statistics**: `ebpf-nat`의 Prometheus 엔드포인트(`/metrics`)에서 `ebpf_nat_packets_total` 및 `ebpf_nat_active_sessions` 수집.
3.  **Kernel Logs**: `trace_pipe`를 모니터링하여 부하 중 발생하는 BPF 에러나 드롭 패킷 확인.

## 5. 자동화 계획 (Automation)

1.  `docker-compose.perf.yaml` 작성: 컨테이너 및 네트워크 설정 정의.
2.  `scripts/run-perf-test.sh` 작성: 
    *   환경 배포 (Up).
    *   네트워크 라우팅 설정.
    *   시나리오 순차 실행 및 결과 파일(`.log`) 저장.
    *   환경 정리 (Down).

## 6. 성공 기준 (Success Criteria)
*   `t2.micro` 제한 환경 내에서 90% 이상의 CPU 효율로 패킷 처리 가능 여부 확인.
*   메모리 누수 없이 1GB 범위 내에서 안정적인 동작 확인.
*   부하 상황에서도 99% 이상의 패킷 전송 성공률 유지.
