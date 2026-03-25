package metrics

import (
	"log/slog"
	"strconv"

	"github.com/cilium/ebpf"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/tae2089/ebpf-nat/internal/bpf"
)

type Manager interface {
	GetRestorationFailures() uint64
}

type Scraper struct {
	objects             *bpf.NatObjects
	manager             Manager
	packetsTotal        *prometheus.Desc
	bytesTotal          *prometheus.Desc
	activeSessions      *prometheus.Desc
	allocFailures       *prometheus.Desc
	mapUpdateFailures   *prometheus.Desc
	restorationFailures *prometheus.Desc
}

func NewScraper(objs *bpf.NatObjects, mgr Manager, reg prometheus.Registerer) *Scraper {
	s := &Scraper{
		objects: objs,
		manager: mgr,
		packetsTotal: prometheus.NewDesc(
			"ebpf_nat_packets_total",
			"Total number of packets processed by eBPF NAT",
			[]string{"protocol", "direction", "action"},
			nil,
		),
		bytesTotal: prometheus.NewDesc(
			"ebpf_nat_bytes_total",
			"Total number of bytes processed by eBPF NAT",
			[]string{"protocol", "direction", "action"},
			nil,
		),
		activeSessions: prometheus.NewDesc(
			"ebpf_nat_active_sessions",
			"Current number of active sessions in the conntrack map",
			[]string{"table"},
			nil,
		),
		allocFailures: prometheus.NewDesc(
			"ebpf_nat_port_allocation_failures_total",
			"Total number of failed port allocation attempts",
			[]string{"protocol"},
			nil,
		),
		mapUpdateFailures: prometheus.NewDesc(
			"ebpf_nat_map_update_failures_total",
			"Total number of failed map update attempts",
			[]string{"protocol"},
			nil,
		),
		restorationFailures: prometheus.NewDesc(
			"ebpf_nat_session_restoration_failures_total",
			"Total number of failed session restoration attempts from persistence",
			nil,
			nil,
		),
	}

	if reg != nil {
		reg.MustRegister(s)
	}

	return s
}

func (s *Scraper) Describe(ch chan<- *prometheus.Desc) {
	ch <- s.packetsTotal
	ch <- s.bytesTotal
	ch <- s.activeSessions
	ch <- s.allocFailures
	ch <- s.mapUpdateFailures
	ch <- s.restorationFailures
}

func (s *Scraper) Collect(ch chan<- prometheus.Metric) {
	s.collectFromMetricsMap(ch)
	s.collectActiveSessions(ch)
	s.collectRestorationFailures(ch)
}

func (s *Scraper) collectRestorationFailures(ch chan<- prometheus.Metric) {
	if s.manager != nil {
		count := s.manager.GetRestorationFailures()
		ch <- prometheus.MustNewConstMetric(s.restorationFailures, prometheus.CounterValue, float64(count))
	}
}

// BPF action constants matching nat.h definitions
const (
	actionTranslated    = 0
	actionDropped       = 1
	actionPassed        = 2
	actionAllocFail     = 3
	actionMapUpdateFail = 4
)

func (s *Scraper) collectFromMetricsMap(ch chan<- prometheus.Metric) {
	if s.objects.MetricsMap == nil {
		return
	}

	var key bpf.NatMetricsKey
	var values []bpf.NatMetricsValue
	iter := s.objects.MetricsMap.Iterate()

	// Buffer metrics first; only send to channel if iteration completes without error.
	// Sending partial metrics on iteration failure would produce misleading counters.
	var buffered []prometheus.Metric
	for iter.Next(&key, &values) {
		var totalPackets uint64
		var totalBytes uint64
		for _, v := range values {
			totalPackets += v.Packets
			totalBytes += v.Bytes
		}

		proto := protoToString(key.Protocol)
		dir := dirToString(key.Direction)
		act := actionToString(key.Action)

		switch key.Action {
		case actionAllocFail:
			buffered = append(buffered, prometheus.MustNewConstMetric(s.allocFailures, prometheus.CounterValue, float64(totalPackets), proto))
		case actionMapUpdateFail:
			buffered = append(buffered, prometheus.MustNewConstMetric(s.mapUpdateFailures, prometheus.CounterValue, float64(totalPackets), proto))
		default:
			buffered = append(buffered, prometheus.MustNewConstMetric(s.packetsTotal, prometheus.CounterValue, float64(totalPackets), proto, dir, act))
			buffered = append(buffered, prometheus.MustNewConstMetric(s.bytesTotal, prometheus.CounterValue, float64(totalBytes), proto, dir, act))
		}
	}

	if err := iter.Err(); err != nil {
		slog.Error("Failed to iterate metrics map, skipping partial results", slog.Any("error", err))
		return
	}

	for _, m := range buffered {
		ch <- m
	}
}

func (s *Scraper) collectActiveSessions(ch chan<- prometheus.Metric) {
	if s.objects.ConntrackMap != nil {
		count := countMapEntries(s.objects.ConntrackMap)
		ch <- prometheus.MustNewConstMetric(s.activeSessions, prometheus.GaugeValue, float64(count), "conntrack")
	}
	if s.objects.ReverseNatMap != nil {
		count := countMapEntries(s.objects.ReverseNatMap)
		ch <- prometheus.MustNewConstMetric(s.activeSessions, prometheus.GaugeValue, float64(count), "reverse_nat")
	}
}

func countMapEntries(m *ebpf.Map) uint64 {
	if m == nil {
		return 0
	}
	var count uint64
	iter := m.Iterate()
	// Use raw bytes to avoid specific type dependency while being safe for any map
	key := make([]byte, m.KeySize())
	value := make([]byte, m.ValueSize())
	for iter.Next(&key, &value) {
		count++
	}
	return count
}

func protoToString(p uint8) string {
	switch p {
	case 1:
		return "icmp"
	case 6:
		return "tcp"
	case 17:
		return "udp"
	default:
		return "proto_" + strconv.Itoa(int(p))
	}
}

func dirToString(d uint8) string {
	if d == 0 {
		return "ingress"
	}
	return "egress"
}

func actionToString(a uint8) string {
	switch a {
	case actionTranslated:
		return "translated"
	case actionDropped:
		return "dropped"
	case actionPassed:
		return "passed"
	case actionAllocFail:
		return "alloc_fail"
	case actionMapUpdateFail:
		return "map_update_fail"
	default:
		return "unknown"
	}
}
