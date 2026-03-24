package metrics

import (
	"log/slog"
	"strconv"

	"github.com/cilium/ebpf"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/tae2089/ebpf-nat/internal/bpf"
)

type Scraper struct {
	objects        *bpf.NatObjects
	packetsTotal   *prometheus.Desc
	bytesTotal     *prometheus.Desc
	activeSessions *prometheus.Desc
	allocFailures  *prometheus.Desc
}

func NewScraper(objs *bpf.NatObjects, reg prometheus.Registerer) *Scraper {
	s := &Scraper{
		objects: objs,
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
}

func (s *Scraper) Collect(ch chan<- prometheus.Metric) {
	s.collectFromMetricsMap(ch)
	s.collectActiveSessions(ch)
}

func (s *Scraper) collectFromMetricsMap(ch chan<- prometheus.Metric) {
	if s.objects.MetricsMap == nil {
		return
	}

	var key bpf.NatMetricsKey
	var values []bpf.NatMetricsValue
	iter := s.objects.MetricsMap.Iterate()

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

		if key.Action == 3 { // ACTION_ALLOC_FAIL
			ch <- prometheus.MustNewConstMetric(s.allocFailures, prometheus.CounterValue, float64(totalPackets), proto)
		} else {
			ch <- prometheus.MustNewConstMetric(s.packetsTotal, prometheus.CounterValue, float64(totalPackets), proto, dir, act)
			ch <- prometheus.MustNewConstMetric(s.bytesTotal, prometheus.CounterValue, float64(totalBytes), proto, dir, act)
		}
	}

	if err := iter.Err(); err != nil {
		slog.Error("Failed to iterate metrics map", slog.Any("error", err))
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
	// Use any to avoid specific type dependency for counting
	var key any
	var value any
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
	case 0:
		return "translated"
	case 1:
		return "dropped"
	case 2:
		return "passed"
	case 3: // ACTION_ALLOC_FAIL
		return "alloc_fail"
	default:
		return "unknown"
	}
}
