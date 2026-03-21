package main

import (
	"flag"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/imtaebin/ebpf-nat/internal/bpf"
	"github.com/imtaebin/ebpf-nat/internal/nat"
	"github.com/vishvananda/netlink"
	"github.com/cilium/ebpf/rlimit"
)

func main() {
	ifaceName := flag.String("iface", "", "Network interface name (e.g. eth0)")
	flag.Parse()

	if *ifaceName == "" {
		slog.Error("Network interface name is required (-iface)")
		os.Exit(1)
	}

	// Remove memlock limit for eBPF
	if err := rlimit.RemoveMemlock(); err != nil {
		slog.Error("Failed to remove memlock limit", slog.Any("error", err))
		os.Exit(1)
	}

	// Load BPF objects
	objs := bpf.NatObjects{}
	if err := bpf.LoadNatObjects(&objs, nil); err != nil {
		slog.Error("Failed to load BPF objects", slog.Any("error", err))
		os.Exit(1)
	}
	defer objs.Close()

	// Initialize NAT Manager
	natMgr := nat.NewManager(&objs)

	// Add a sample SNAT rule for testing
	// Example: Packets from 192.168.1.10:12345 to 8.8.8.8:53 (UDP) 
	// should be translated to 10.0.0.1:54321
	err := natMgr.AddSNATRule(
		net.ParseIP("192.168.1.10"), net.ParseIP("8.8.8.8"),
		12345, 53, syscall.IPPROTO_UDP,
		net.ParseIP("10.0.0.1"), 54321,
	)
	if err != nil {
		slog.Error("Failed to add test SNAT rule", slog.Any("error", err))
	} else {
		slog.Info("Added sample SNAT rule for testing")
	}

	// Find the network interface
	link, err := netlink.LinkByName(*ifaceName)
	if err != nil {
		slog.Error("Failed to find interface", slog.String("name", *ifaceName), slog.Any("error", err))
		os.Exit(1)
	}

	// Add qdisc clsact for TC
	qdisc := &netlink.GenericQdisc{
		QdiscAttrs: netlink.QdiscAttrs{
			LinkIndex: link.Attrs().Index,
			Handle:    netlink.MakeHandle(0xffff, 0),
			Parent:    netlink.HANDLE_CLSACT,
		},
		QdiscType: "clsact",
	}

	if err := netlink.QdiscReplace(qdisc); err != nil {
		slog.Error("Failed to add clsact qdisc", slog.Any("error", err))
		os.Exit(1)
	}

	// Filter for Ingress
	filterIngress := &netlink.BpfFilter{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: link.Attrs().Index,
			Parent:    netlink.HANDLE_MIN_INGRESS,
			Handle:    netlink.MakeHandle(0, 1),
			Protocol:  syscall.ETH_P_ALL,
			Priority:  1,
		},
		Fd:           objs.TcNatProg.FD(),
		Name:         "tc_nat_ingress",
		DirectAction: true,
	}

	if err := netlink.FilterReplace(filterIngress); err != nil {
		slog.Error("Failed to attach BPF program to ingress", slog.Any("error", err))
		os.Exit(1)
	}

	// Filter for Egress
	filterEgress := &netlink.BpfFilter{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: link.Attrs().Index,
			Parent:    netlink.HANDLE_MIN_EGRESS,
			Handle:    netlink.MakeHandle(0, 1),
			Protocol:  syscall.ETH_P_ALL,
			Priority:  1,
		},
		Fd:           objs.TcNatProg.FD(),
		Name:         "tc_nat_egress",
		DirectAction: true,
	}

	if err := netlink.FilterReplace(filterEgress); err != nil {
		slog.Error("Failed to attach BPF program to egress", slog.Any("error", err))
		os.Exit(1)
	}

	slog.Info("Successfully attached eBPF NAT program to interface (Ingress & Egress)", slog.String("interface", *ifaceName))

	// Wait for termination
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	<-stop

	slog.Info("Detaching eBPF program and exiting...")
}
