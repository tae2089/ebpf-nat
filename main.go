//go:build linux
// +build linux

package main

import (
	"context"
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/imtaebin/ebpf-nat/internal/bpf"
	"github.com/imtaebin/ebpf-nat/internal/config"
	"github.com/imtaebin/ebpf-nat/internal/nat"
	"github.com/vishvananda/netlink"
	"github.com/cilium/ebpf/rlimit"
)

func main() {
	configPath := flag.String("config", "config.yaml", "Path to configuration file")
	ipDetectType := flag.String("ip-detect-type", "", "IP detection type (generic, aws, gcp, auto)")
	ipDetectInterval := flag.Duration("ip-detect-interval", 5*time.Minute, "IP detection interval")
	flag.Parse()

	// Load configuration
	cfg, err := config.LoadConfig(*configPath)
	if err != nil {
		slog.Error("Failed to load config", slog.Any("error", err))
		os.Exit(1)
	}

	if cfg.Interface == "" {
		slog.Error("Network interface name is required in config")
		os.Exit(1)
	}

	// Override config with flags if provided
	if *ipDetectType != "" {
		cfg.IPDetectType = *ipDetectType
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

	// Initialize NAT Manager and load rules
	natMgr := nat.NewManager(&objs)
	if err := natMgr.LoadConfig(cfg); err != nil {
		slog.Error("Failed to load NAT rules from config", slog.Any("error", err))
		os.Exit(1)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start background tasks
	go natMgr.RunBackgroundTasks(ctx, *ipDetectInterval)

	// Find the network interface
	link, err := netlink.LinkByName(cfg.Interface)
	if err != nil {
		slog.Error("Failed to find interface", slog.String("name", cfg.Interface), slog.Any("error", err))
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

	slog.Info("Successfully started eBPF NAT", slog.String("interface", cfg.Interface))

	// Wait for termination
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	<-stop

	cancel() // Stop background tasks
	slog.Info("Detaching eBPF program and exiting...")
}
