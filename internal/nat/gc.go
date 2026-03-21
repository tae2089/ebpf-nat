package nat

import (
	"context"
	"log/slog"
	"syscall"
	"time"

	"github.com/imtaebin/ebpf-nat/internal/bpf"
)

type GarbageCollector struct {
	objects    *bpf.NatObjects
	tcpTimeout time.Duration
	udpTimeout time.Duration
}

func NewGarbageCollector(objs *bpf.NatObjects, tcpTimeout, udpTimeout time.Duration) *GarbageCollector {
	return &GarbageCollector{
		objects:    objs,
		tcpTimeout: tcpTimeout,
		udpTimeout: udpTimeout,
	}
}

func (gc *GarbageCollector) RunOnce(ctx context.Context, now uint64) error {
	slog.Debug("Starting NAT map garbage collection")

	iter := gc.objects.ConntrackMap.Iterate()
	var key bpf.NatNatKey
	var entry bpf.NatNatEntry
	var expiredCount int

	for iter.Next(&key, &entry) {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		var timeout time.Duration
		switch key.Protocol {
		case syscall.IPPROTO_TCP:
			timeout = gc.tcpTimeout
		case syscall.IPPROTO_UDP:
			timeout = gc.udpTimeout
		default:
			// Fallback timeout for other protocols
			timeout = gc.udpTimeout
		}

		// Calculate age in nanoseconds
		age := now - entry.LastSeen

		if age > uint64(timeout.Nanoseconds()) {
			slog.Debug("Evicting expired session", 
				slog.Any("key", key), 
				slog.Duration("age", time.Duration(age)))

			// 1. Delete from conntrack_map
			if err := gc.objects.ConntrackMap.Delete(key); err != nil {
				slog.Warn("Failed to delete from conntrack_map", slog.Any("error", err))
				continue // Skip reverse map deletion if primary fails
			}

			// 2. Delete from reverse_nat_map
			// The reverse key swaps Src/Dst and uses the translated values for the destination
			revKey := bpf.NatNatKey{
				SrcIp:    key.DstIp,
				DstIp:    entry.TranslatedIp,
				SrcPort:  key.DstPort,
				DstPort:  entry.TranslatedPort,
				Protocol: key.Protocol,
			}
			
			if err := gc.objects.ReverseNatMap.Delete(revKey); err != nil {
				slog.Warn("Failed to delete from reverse_nat_map", slog.Any("error", err))
			}
			
			expiredCount++
		}
	}

	if err := iter.Err(); err != nil {
		return err
	}

	if expiredCount > 0 {
		slog.Info("Garbage collection completed", slog.Int("evicted_sessions", expiredCount))
	} else {
		slog.Debug("Garbage collection completed, no sessions evicted")
	}

	return nil
}
