CC=clang
BPF_GEN_DIR=internal/bpf
BPF_SRC=bpf/nat.c
BUILDER_IMAGE=ebpf-nat-builder

.PHONY: all generate build test clean build-builder

all: generate build

build-builder:
	docker build -t $(BUILDER_IMAGE) -f Dockerfile.ebpf .

generate: build-builder
	docker run --rm -v $(shell pwd):/app -w /app $(BUILDER_IMAGE) \
		go generate ./...

build: generate
	GOOS=linux GOARCH=amd64 go build -o bin/ebpf-nat-amd64 main.go
	GOOS=linux GOARCH=arm64 go build -o bin/ebpf-nat-arm64 main.go

test: generate
	docker run --rm --privileged \
		-v /sys/kernel/debug:/sys/kernel/debug \
		-v $(shell pwd):/app -w /app $(BUILDER_IMAGE) \
		go test -v ./...

clean:
	rm -rf bin/
	rm -f $(BPF_GEN_DIR)/*.go
	rm -f bpf/*.o
