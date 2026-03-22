# Spec: GoReleaser CI/CD Pipeline

## Overview
Implement an automated CI/CD pipeline using GitHub Actions and GoReleaser. The pipeline will trigger on new tags to build, cross-compile, and release the `ebpf-nat` binary for Linux (amd64 and arm64).

## Requirements
- Trigger on GitHub tag pushes (`v*`).
- Install eBPF dependencies (`clang`, `llvm`, `libbpf-dev`) on the runner.
- Execute `go generate ./...` before building.
- Use GoReleaser to cross-compile (linux/amd64, linux/arm64) without CGO.
- Package binaries into `.tar.gz` archives with checksums.
