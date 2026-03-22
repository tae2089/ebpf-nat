//go:build linux
// +build linux

package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/imtaebin/ebpf-nat/internal/bpf"
	"github.com/imtaebin/ebpf-nat/internal/config"
	"github.com/imtaebin/ebpf-nat/internal/nat"
	"github.com/imtaebin/ebpf-nat/internal/metrics"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/vishvananda/netlink"
	"github.com/cilium/ebpf/rlimit"
)

func main() {
	configPath := flag.String("config", "config.yaml", "Path to configuration file")
	debug := flag.Bool("debug", false, "Enable debug logging and BPF tracing")
	ipDetectType := flag.String("ip-detect-type", "", "IP detection type (generic, aws, gcp, auto)")
	ipDetectInterval := flag.Duration("ip-detect-interval", 5*time.Minute, "IP detection interval")
	gcIntervalStr := flag.String("gc-interval", "", "Garbage collection interval (e.g., 1m)")
	tcpTimeoutStr := flag.String("tcp-timeout", "", "TCP session timeout (e.g., 24h)")
	udpTimeoutStr := flag.String("udp-timeout", "", "UDP session timeout (e.g., 5m)")
	metricsEnabled := flag.Bool("metrics-enabled", false, "Enable Prometheus metrics")
	metricsPort := flag.Int("metrics-port", 0, "Prometheus metrics port")
	flag.Parse()

	// Set log level
	logLevel := slog.LevelInfo
	if *debug {
		logLevel = slog.LevelDebug
	}
	opts := &slog.HandlerOptions{Level: logLevel}
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stdout, opts)))

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
	if *gcIntervalStr != "" {
		cfg.GCInterval = *gcIntervalStr
	}
	if *tcpTimeoutStr != "" {
		cfg.TCPTimeout = *tcpTimeoutStr
	}
	if *udpTimeoutStr != "" {
		cfg.UDPTimeout = *udpTimeoutStr
	}
	if *metricsEnabled {
		cfg.Metrics.Enabled = true
	}
	if *metricsPort != 0 {
		cfg.Metrics.Port = *metricsPort
	}

	// Parse duration settings with defaults
	gcInterval := 1 * time.Minute
	if cfg.GCInterval != "" {
		if d, err := time.ParseDuration(cfg.GCInterval); err == nil {
			gcInterval = d
		}
	}
	tcpTimeout := 24 * time.Hour
	if cfg.TCPTimeout != "" {
		if d, err := time.ParseDuration(cfg.TCPTimeout); err == nil {
			tcpTimeout = d
		}
	}
	udpTimeout := 5 * time.Minute
	if cfg.UDPTimeout != "" {
		if d, err := time.ParseDuration(cfg.UDPTimeout); err == nil {
			udpTimeout = d
		}
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

	if *debug {
		go bpf.StartTracePipeLogger(ctx)
	}

	// Start background tasks
	go natMgr.RunBackgroundTasks(ctx, *ipDetectInterval, gcInterval, tcpTimeout, udpTimeout)

	// Start metrics server if enabled
	if cfg.Metrics.Enabled {
		if cfg.Metrics.Port == 0 {
			cfg.Metrics.Port = 9090
		}
		if cfg.Metrics.Address == "" {
			cfg.Metrics.Address = "0.0.0.0"
		}

		metrics.NewScraper(&objs, prometheus.DefaultRegisterer)
		addr := fmt.Sprintf("%s:%d", cfg.Metrics.Address, cfg.Metrics.Port)

		mux := http.NewServeMux()
		mux.Handle("/metrics", promhttp.Handler())

		server := &http.Server{
			Addr:    addr,
			Handler: mux,
		}

		go func() {
			slog.Info("Starting metrics server", slog.String("addr", addr))
			if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				slog.Error("Metrics server failed", slog.Any("error", err))
			}
		}()

		go func() {
			<-ctx.Done()
			slog.Info("Shutting down metrics server")
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			server.Shutdown(shutdownCtx)
		}()
	}

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
