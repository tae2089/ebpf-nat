CC=clang
BPF_GEN_DIR=internal/bpf
BPF_SRC=bpf/nat.c
BUILDER_IMAGE=ebpf-nat-builder
GOMODCACHE=$(shell go env GOMODCACHE 2>/dev/null || echo "$(shell pwd)/.go-cache/pkg/mod")
GOCACHE=$(shell go env GOCACHE 2>/dev/null || echo "$(shell pwd)/.go-cache/go-build")

.PHONY: all generate build test clean build-builder

all: generate build

build-builder:
	docker build -t $(BUILDER_IMAGE) -f Dockerfile.ebpf .

generate: build-builder
	mkdir -p $(GOMODCACHE) $(GOCACHE)
	docker run --rm \
		-v $(GOMODCACHE):/go/pkg/mod \
		-v $(GOCACHE):/root/.cache/go-build \
		-v $(shell pwd):/app -w /app $(BUILDER_IMAGE) \
		go generate ./...

build: generate
	GOOS=linux GOARCH=amd64 go build -o bin/ebpf-nat-amd64 main.go
	GOOS=linux GOARCH=arm64 go build -o bin/ebpf-nat-arm64 main.go

test: generate
	mkdir -p $(GOMODCACHE) $(GOCACHE)
	docker run --rm --privileged \
		-v /sys/kernel/debug:/sys/kernel/debug \
		-v $(GOMODCACHE):/go/pkg/mod \
		-v $(GOCACHE):/root/.cache/go-build \
		-v $(shell pwd):/app -w /app $(BUILDER_IMAGE) \
		go test -v ./...

integration-test: generate
	mkdir -p $(GOMODCACHE) $(GOCACHE)
	docker run --rm --privileged \
		-v /sys/kernel/debug:/sys/kernel/debug \
		-v $(GOMODCACHE):/go/pkg/mod \
		-v $(GOCACHE):/root/.cache/go-build \
		-v $(shell pwd):/app -w /app $(BUILDER_IMAGE) \
		go test -v ./internal/nat -run TestNATConnectivity

clean:
	rm -rf bin/
	rm -f $(BPF_GEN_DIR)/*.go
	rm -f bpf/*.o
