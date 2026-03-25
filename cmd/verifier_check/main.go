//go:build linux

package main

import (
	"fmt"
	"os"

	"github.com/cilium/ebpf/rlimit"
	"github.com/tae2089/ebpf-nat/internal/bpf"
)

func main() {
	rlimit.RemoveMemlock()
	objs := bpf.NatObjects{}
	if err := bpf.LoadNatObjects(&objs, nil); err != nil {
		fmt.Fprintf(os.Stderr, "BPF load error:\n%+v\n", err)
		os.Exit(1)
	}
	fmt.Println("BPF programs loaded successfully")
	objs.Close()
}
