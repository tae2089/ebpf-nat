# Tasks: Security Hardening (보안 전문가 3인 취약점 수정)

## 1. [Critical] G-3: ipToUint32 NativeEndian → BigEndian 수정
- [x] Red: `ipToUint32`가 BigEndian을 사용하는지 검증하는 단위 테스트 작성 (security_test.go 존재)
- [x] Green: `binary.NativeEndian` → `binary.BigEndian` 수정 (ipToUint32, internalMask)
- [x] Verify: integration_test.go, map_test.go의 BigEndian 참조도 업데이트

## 2. [High] G-2: RestoreSessions age 계산 언더플로우 방어
- [x] Red: `entry.LastSeenUnix > nowUnix`인 경우 세션이 건너뛰어지는지 테스트 (TestRestoreSessionsAgeGuard_FutureTimestamp 추가)
- [x] Green: age 계산 전 `if entry.LastSeenUnix > nowUnix { continue }` 추가

## 3. [High] S-1: IP 탐지 서비스 HTTP → HTTPS + TLS 설정
- [x] Red: HTTPS URL 사용 여부 검증 테스트 작성 (TestGenericDetector_DefaultURLIsHTTPS)
- [x] Green: `http://icanhazip.com` → `https://icanhazip.com` 변경

## 4. [High] G-1: LoadConfig 뮤텍스 해제 구간 경쟁 조건 개선
- [x] 분석 완료 — 이미 Iteration 1에서 수정됨 (setSNATConfigLocked 패턴으로 해결)

## 5. [Medium] G-5: 설정 타임아웃 최솟값 검증
- [x] Red: 각 타임아웃에 대한 최솟값 미달 테스트 케이스 추가 (6건)
- [x] Green: config.go에 최솟값 검증 로직 추가
  - GC 간격: 최소 1초
  - TCP 타임아웃: 최소 1분
  - UDP 타임아웃: 최소 10초

## 6. [Medium] G-4: 외부 응답 로그 인젝션 방어 (sanitize 함수)
- [x] Red: sanitizeExternalResponse 함수 단위 테스트 작성 (9건, TestSanitizeExternalResponse)
- [x] Green: `sanitizeExternalResponse` 함수 구현 (max 40자, 비ASCII/제어 문자 제거)
- [x] 적용: generic.go 에러 메시지, aws.go 에러 메시지

## 7. [Medium] G-6: IMDSv2 토큰 제어 문자 필터링
- [x] Red: 토큰에 \r\n이 포함될 때 필터링되는지 테스트 (TestAWSDetector_TokenFilterControlChars)
- [x] Green: getToken()에서 sanitizeExternalResponse(strings.TrimSpace(token)) 적용

## 8. [BPF/C] C-1: metrics_key 구조체 패딩 zero-initialization
- [x] Green: `struct metrics_key key = {};` 로 수정 후 필드 개별 할당

## 9. [BPF/C] C-2: ICMP 에러 처리 inner IP IHL 검증
- [x] Green: apply_nat_icmp_error에서 inner_iph->ihl != 5 시 TC_ACT_OK 반환 추가

## 10. [Systemd] E-1: CAP_SYS_ADMIN 제거, CAP_BPF + CAP_NET_ADMIN으로 교체
- [x] Green: CapabilityBoundingSet에서 CAP_SYS_ADMIN 제거, AmbientCapabilities 추가

---

## 신규 보안 개선사항 (보안 전문가 3인 2차 검토)

## 11. [High] 공인 IP 탐지 결과 검증 (validatePublicIP)
- [x] Red: `validatePublicIP` 함수 단위 테스트 작성 (ipdetect 패키지)
  - loopback, private, unspecified, multicast, link-local, IPv6 각각 거부 테스트
  - 정상 공인 IP는 통과 테스트
- [x] Green: `ValidatePublicIP(ip net.IP) error` 공개 함수 구현 (internal/ipdetect/generic.go)
- [x] Apply: `manager.go`의 `updatePublicIP()`에서 `SetSNATConfig()` 호출 직전 검증 추가

## 12. [High] DNAT/SNAT transIP 입력 검증 (validateTranslationIP)
- [x] Red: `validateTranslationIP` 함수 단위 테스트 작성 (config 패키지, 9건)
  - loopback, multicast, unspecified, broadcast, link-local 각각 거부 테스트
  - 정상 사설/공인 IP는 통과 테스트
- [x] Green: `validateTranslationIP(ip net.IP) error` 헬퍼 함수 구현 (config.go)
- [x] Apply1: `config.go`의 `Rule.Validate()` TransIP 검증 부분에 적용
- [x] Apply2: `manager.go`의 `AddDNATRule()`, `AddSNATRule()`에 `validateTranslationIPForNAT()` 적용

## 13. [High] 세션 파일 HMAC-SHA256 무결성 검증
- [x] Red: HMAC 서명/검증 테스트 작성 (persistence_test.go)
  - 정상 저장/복원 시 성공 테스트 (TestSaveAndRestoreSessions_HMACIntegrity)
  - HMAC 불일치 시 에러 반환 테스트 (TestRestoreSessions_HMACTampering)
  - 키 파일 없을 때 경고 후 복원 성공 테스트 (TestRestoreSessions_NoHMACKey_WarnsAndRestores)
- [x] Green: SessionSnapshot에 HMAC 필드 추가 (persistence.go)
- [x] Green: SaveSessions에서 HMAC 서명 추가 — 파일 형식: `[gzip(gob)][32-byte HMAC][4-byte magic "EBPF"]`
- [x] Green: RestoreSessions에서 magic bytes로 HMAC trailer 감지 후 검증 (하위 호환)

## 14. [Medium] 세션 복원 실패 임계값 설정
- [x] Red: 실패율 초과 시 에러 반환 테스트 작성 (TestRestorationFailureThreshold_ExceedLimit)
- [x] Green: Config에 RestorationFailureThreshold float64 추가 (기본값 0.5), 범위 검증 포함
- [x] Green: Manager에 restorationFailureThreshold 필드 추가, RestoreSessions 끝에서 실패율 검사
- [x] Apply: LoadConfig에서 설정값 로드, main.go는 기존 에러 로깅 유지

## 15. [Medium] 메트릭 엔드포인트 Bearer Token 인증
- [x] Red: Bearer Token 인증 미들웨어 테스트 작성 (TestBearerTokenMiddleware, 7건)
  - 토큰 설정 시 올바른 토큰 통과 테스트
  - 토큰 설정 시 잘못된 토큰 401 응답 테스트
  - 토큰 미설정 시 기존 동작 유지 테스트
- [x] Green: MetricsConfig에 BearerToken 필드 추가 (config.go)
- [x] Green: `BearerTokenMiddleware` 구현 (internal/metrics/auth.go), ConstantTimeCompare 사용
- [x] Apply: main.go에서 `/metrics` 핸들러를 미들웨어로 래핑, `--metrics-bearer-token` CLI 플래그 추가
- [x] Apply: Config.Validate()에서 비localhost + 빈 토큰 경고 (slog.Warn)

## 16. [Medium] systemd 추가 보안 하드닝
- [x] Green: ebpf-nat.service에 추가 directives 적용
  - SystemCallFilter=@system-service bpf perf_event_open
  - SystemCallArchitectures=native
  - RestrictAddressFamilies=AF_INET AF_INET6 AF_NETLINK AF_UNIX
  - RestrictNamespaces=yes
  - ProtectKernelTunables=yes, ProtectKernelLogs=yes, ProtectControlGroups=yes
  - ProtectClock=yes, LockPersonality=yes, ProtectHostname=yes

## 17. [Medium] GC per-source 세션 수 모니터링
- [x] Red: per-source 세션 수 초과 경고 테스트 작성 (TestGarbageCollector_PerSourceSessionWarning, TestGarbageCollector_PerSourceDisabled)
- [x] Green: GarbageCollector에 maxSessionsPerSource uint32 필드 추가 (gc.go)
- [x] Green: RunOnce()에서 소스 IP별 카운터 구축 및 임계값 초과 시 slog.Warn 출력
- [x] Green: `sessionLimitWarningsTotal` 전역 카운터 추가 (atomic.Uint64)
