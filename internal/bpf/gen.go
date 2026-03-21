package bpf

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpf -type nat_key -type nat_entry Nat ../../bpf/nat.c -- -I.
