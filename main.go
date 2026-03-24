//go:build linux
// +build linux

package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/cilium/ebpf/rlimit"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/spf13/cobra"
	"github.com/tae2089/ebpf-nat/internal/bpf"
	"github.com/tae2089/ebpf-nat/internal/config"
	"github.com/tae2089/ebpf-nat/internal/metrics"
	"github.com/tae2089/ebpf-nat/internal/nat"
	"github.com/vishvananda/netlink"
)

var (
	cfg              = &config.Config{}
	debug            bool
	ipDetectInterval time.Duration
)

var rootCmd = &cobra.Command{
	Use:   "ebpf-nat",
	Short: "High-performance TC-based NAT with eBPF",
	Run: func(cmd *cobra.Command, args []string) {
		run()
	},
}

func init() {
	rootCmd.Flags().StringVarP(&cfg.Interface, "interface", "i", "", "Network interface to attach eBPF (required)")
	rootCmd.MarkFlagRequired("interface")

	rootCmd.Flags().BoolVarP(&debug, "debug", "d", false, "Enable debug logging and BPF tracing")
	rootCmd.Flags().BoolVarP(&cfg.Masquerade, "masquerade", "m", true, "Enable dynamic SNAT (masquerading)")
	rootCmd.Flags().StringVar(&cfg.ExternalIP, "external-ip", "", "Static external IP for SNAT (overrides detection)")
	rootCmd.Flags().StringVar(&cfg.InternalNet, "internal-net", "", "Internal network CIDR for Anti-Spoofing (e.g., 192.168.1.0/24)")
	rootCmd.Flags().StringVar(&cfg.IPDetectType, "ip-detect-type", "auto", "IP detection type (generic, aws, gcp, auto)")
	rootCmd.Flags().DurationVar(&ipDetectInterval, "ip-detect-interval", 5*time.Minute, "IP detection interval")
	rootCmd.Flags().StringVar(&cfg.GCInterval, "gc-interval", "1m", "Garbage collection interval")
	rootCmd.Flags().StringVar(&cfg.TCPTimeout, "tcp-timeout", "24h", "TCP session timeout")
	rootCmd.Flags().StringVar(&cfg.UDPTimeout, "udp-timeout", "5m", "UDP session timeout")
	rootCmd.Flags().Uint16Var(&cfg.MaxMSS, "max-mss", 0, "TCP MSS clamping value (0 to disable)")
	rootCmd.Flags().Uint32Var(&cfg.MaxSessions, "max-sessions", 65536, "Maximum NAT sessions")
	rootCmd.Flags().Uint32Var(&cfg.BatchUpdateSize, "batch-update-size", 1000, "Batch update size for session restoration")
	rootCmd.Flags().StringVar(&cfg.SessionFile, "session-file", "/var/lib/ebpf-nat/sessions.gob", "Path to save/restore sessions")

	rootCmd.Flags().BoolVar(&cfg.Metrics.Enabled, "metrics-enabled", false, "Enable Prometheus metrics")
	rootCmd.Flags().StringVar(&cfg.Metrics.Address, "metrics-address", "0.0.0.0", "Prometheus metrics listen address")
	rootCmd.Flags().IntVar(&cfg.Metrics.Port, "metrics-port", 9090, "Prometheus metrics port")
}

func run() {
	// Validate configuration
	if err := cfg.Validate(); err != nil {
		slog.Error("Configuration validation failed", slog.Any("error", err))
		os.Exit(1)
	}

	// Set log level
	logLevel := slog.LevelInfo
	if debug {
		logLevel = slog.LevelDebug
	}
	opts := &slog.HandlerOptions{Level: logLevel}
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stdout, opts)))

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

	// Load BPF spec to modify map sizes if needed
	spec, err := bpf.LoadNat()
	if err != nil {
		slog.Error("Failed to load BPF spec", slog.Any("error", err))
		os.Exit(1)
	}

	if cfg.MaxSessions > 0 {
		if m, ok := spec.Maps["conntrack_map"]; ok {
			m.MaxEntries = cfg.MaxSessions
		}
		if m, ok := spec.Maps["reverse_nat_map"]; ok {
			m.MaxEntries = cfg.MaxSessions
		}
		slog.Info("Adjusting map sizes", slog.Uint64("max_sessions", uint64(cfg.MaxSessions)))
	}

	// Load BPF objects from spec
	objs := bpf.NatObjects{}
	if err := spec.LoadAndAssign(&objs, nil); err != nil {
		slog.Error("Failed to load BPF objects", slog.Any("error", err))
		os.Exit(1)
	}
	defer objs.Close()

	// Initialize NAT Manager and apply config
	natMgr := nat.NewManager(&objs)
	if err := natMgr.LoadConfig(cfg); err != nil {
		slog.Error("Failed to apply NAT configuration", slog.Any("error", err))
		os.Exit(1)
	}

	// Restore sessions if the session file exists
	if cfg.SessionFile != "" {
		if err := natMgr.RestoreSessions(cfg.SessionFile); err != nil {
			slog.Error("Failed to restore sessions", slog.String("path", cfg.SessionFile), slog.Any("error", err))
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var wg sync.WaitGroup

	if debug {
		wg.Add(1)
		go func() {
			defer wg.Done()
			bpf.StartTracePipeLogger(ctx)
		}()
	}

	// Start background tasks
	wg.Add(1)
	go func() {
		defer wg.Done()
		natMgr.RunBackgroundTasks(ctx, ipDetectInterval, gcInterval, tcpTimeout, udpTimeout)
	}()

	// Start metrics server if enabled
	if cfg.Metrics.Enabled {
		metrics.NewScraper(&objs, natMgr, prometheus.DefaultRegisterer)
		addr := fmt.Sprintf("%s:%d", cfg.Metrics.Address, cfg.Metrics.Port)

		mux := http.NewServeMux()
		mux.Handle("/metrics", promhttp.Handler())

		server := &http.Server{
			Addr:    addr,
			Handler: mux,
		}

		wg.Add(1)
		go func() {
			defer wg.Done()
			slog.Info("Starting metrics server", slog.String("addr", addr))
			if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				slog.Error("Metrics server failed", slog.Any("error", err))
			}
		}()

		wg.Add(1)
		go func() {
			defer wg.Done()
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
		Fd:           objs.TcNatIngress.FD(),
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
		Fd:           objs.TcNatEgress.FD(),
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

	slog.Info("Shutting down gracefully...")

	// 1. Mark manager as stopping and cancel context to stop background tasks
	natMgr.Shutdown()
	cancel()

	// 2. Detach eBPF programs first to stop processing new packets
	slog.Info("Detaching eBPF programs from interface", slog.String("interface", cfg.Interface))

	// Detach filters - continue even if one fails
	if err := netlink.FilterDel(filterIngress); err != nil {
		slog.Error("Failed to detach ingress filter", slog.Any("error", err))
	} else {
		slog.Debug("Successfully detached ingress filter")
	}

	if err := netlink.FilterDel(filterEgress); err != nil {
		slog.Error("Failed to detach egress filter", slog.Any("error", err))
	} else {
		slog.Debug("Successfully detached egress filter")
	}

	// 3. Wait for all background tasks to complete with a timeout
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	// Create a timeout for the shutdown process
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()

	select {
	case <-done:
		slog.Info("All background tasks stopped")
	case <-shutdownCtx.Done():
		slog.Warn("Shutdown timed out waiting for background tasks")
	}

	// 4. Save sessions now that everything is stopped
	if cfg.SessionFile != "" {
		if err := natMgr.SaveSessions(cfg.SessionFile); err != nil {
			slog.Error("Failed to save sessions", slog.String("path", cfg.SessionFile), slog.Any("error", err))
		}
	}

	slog.Info("Shutdown complete, exiting...")
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
