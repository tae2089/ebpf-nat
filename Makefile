CC=clang
CFLAGS=-O2 -g -target bpf -Wall -Werror $(EXTRA_CFLAGS)
BPF_GEN_DIR=internal/bpf
BPF_SRC=bpf/nat.c

.PHONY: all generate build test clean

all: generate build

generate:
	go generate ./...

build: generate
	go build -o bin/ebpf-nat main.go

test: generate
	go test -v ./...

clean:
	rm -rf bin/
	rm -f $(BPF_GEN_DIR)/*.go
	rm -f bpf/*.o
