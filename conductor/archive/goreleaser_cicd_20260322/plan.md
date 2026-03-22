# Plan: GoReleaser CI/CD Pipeline

## Objective
GoReleaser와 GitHub Actions를 통합하여, GitHub에 태그(Tag)가 푸시될 때마다 `ebpf-nat` 프로젝트의 크로스 컴파일(amd64, arm64) 및 릴리스 배포를 자동으로 수행하는 CI/CD 파이프라인을 구축합니다.

## Key Context
- `ebpf-nat`는 eBPF C 코드를 포함하고 있으므로, Go 빌드 전에 `go generate`를 통한 BPF 오브젝트 파일 생성(`bpf2go` 활용)이 선행되어야 합니다.
- 따라서 GitHub Actions 워크플로우 러너(Ubuntu) 환경에 `clang`, `llvm`, `libbpf-dev` 등의 의존성을 먼저 설치해야 합니다.
- 빌드 타겟은 Linux 환경(amd64, arm64)으로 제한합니다.

## Implementation Steps

### Phase 1: GoReleaser 설정
- [x] Task: 프로젝트 루트에 `.goreleaser.yaml` 파일을 생성합니다.
  - Linux `amd64` 및 `arm64` 빌드 타겟 설정.
  - CGO를 비활성화(`CGO_ENABLED=0`)하여 정적 링킹 유도.
  - 압축 아카이브(`.tar.gz`) 및 체크섬 생성 설정 포함.

### Phase 2: GitHub Actions 워크플로우 설정
- [x] Task: `.github/workflows/release.yml` 워크플로우 파일을 생성합니다.
  - Trigger: 릴리스 태그(`v*` 형태 등) 푸시 이벤트.
  - Steps:
    1. 소스 코드 체크아웃.
    2. Go 환경 설정 (Go 1.25).
    3. `apt-get`을 활용하여 eBPF 컴파일용 의존성(`clang`, `llvm`, `libbpf-dev`) 설치.
    4. `go generate ./...` 명령어로 eBPF 오브젝트 빌드.
    5. `goreleaser/goreleaser-action`을 실행하여 릴리스 자동화.

## Verification
- 임의시의 로컬 환경에서 `goreleaser release --snapshot --clean`을 실행하여 빌드 프로세스가 정상적으로 동작하는지 확인합니다.
- (승인 후) GitHub 저장소에 코드를 푸시하고, 새 태그를 생성하여 Actions 탭에서 릴리스 파이프라인이 정상적으로 실행되는지 검증합니다.
