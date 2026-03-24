package nat

import (
	"context"
	"errors"
	"log/slog"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/tae2089/ebpf-nat/internal/bpf"
)

const defaultBatchSize = 256

type GarbageCollector struct {
	objects           *bpf.NatObjects
	tcpTimeout        time.Duration
	tcpClosingTimeout time.Duration
	udpTimeout        time.Duration
}

func NewGarbageCollector(objs *bpf.NatObjects, tcpTimeout, udpTimeout time.Duration) *GarbageCollector {
	return &GarbageCollector{
		objects:           objs,
		tcpTimeout:        tcpTimeout,
		tcpClosingTimeout: 2 * time.Minute,
		udpTimeout:        udpTimeout,
	}
}

func (gc *GarbageCollector) RunOnce(ctx context.Context, now uint64) error {
	slog.Debug("Starting NAT map garbage collection")

	// Phase 1: Collect expired keys via BatchLookup
	expiredKeys, expiredRevKeys, err := gc.collectExpiredKeys(ctx, now)
	if err != nil {
		return err
	}

	if len(expiredKeys) == 0 {
		slog.Debug("Garbage collection completed, no sessions evicted")
		return nil
	}

	// Phase 2: Batch delete expired entries
	gc.batchDeleteExpired(expiredKeys, expiredRevKeys)

	slog.Info("Garbage collection completed", slog.Int("evicted_sessions", len(expiredKeys)))
	return nil
}

func (gc *GarbageCollector) collectExpiredKeys(ctx context.Context, now uint64) ([]bpf.NatNatKey, []bpf.NatNatKey, error) {
	var expiredKeys []bpf.NatNatKey
	var expiredRevKeys []bpf.NatNatKey

	var cursor ebpf.MapBatchCursor
	keys := make([]bpf.NatNatKey, defaultBatchSize)
	values := make([]bpf.NatNatEntry, defaultBatchSize)

	for {
		select {
		case <-ctx.Done():
			return nil, nil, ctx.Err()
		default:
		}

		count, err := gc.objects.ConntrackMap.BatchLookup(&cursor, keys, values, nil)

		for i := 0; i < count; i++ {
			key := keys[i]
			entry := values[i]

			var timeout time.Duration
			if entry.State == NatStateClosing {
				timeout = gc.tcpClosingTimeout
			} else {
				switch key.Protocol {
				case syscall.IPPROTO_TCP:
					timeout = gc.tcpTimeout
				case syscall.IPPROTO_UDP:
					timeout = gc.udpTimeout
				default:
					timeout = gc.udpTimeout
				}
			}

			age := now - entry.LastSeen
			if age > uint64(timeout.Nanoseconds()) {
				slog.Debug("Marking expired session for eviction",
					slog.Any("key", key),
					slog.Duration("age", time.Duration(age)))

				expiredKeys = append(expiredKeys, key)
				expiredRevKeys = append(expiredRevKeys, bpf.NatNatKey{
					SrcIp:    key.DstIp,
					DstIp:    entry.TranslatedIp,
					SrcPort:  key.DstPort,
					DstPort:  entry.TranslatedPort,
					Protocol: key.Protocol,
				})
			}
		}

		if errors.Is(err, ebpf.ErrKeyNotExist) {
			// Reached end of map
			break
		}
		if err != nil {
			return nil, nil, err
		}
	}

	return expiredKeys, expiredRevKeys, nil
}

func (gc *GarbageCollector) batchDeleteExpired(expiredKeys, expiredRevKeys []bpf.NatNatKey) {
	// Delete from conntrack_map
	deleted, err := gc.objects.ConntrackMap.BatchDelete(expiredKeys, nil)
	if err != nil {
		slog.Warn("BatchDelete from conntrack_map partially failed",
			slog.Int("deleted", deleted),
			slog.Int("total", len(expiredKeys)),
			slog.Any("error", err))
	}

	// Delete from reverse_nat_map
	deleted, err = gc.objects.ReverseNatMap.BatchDelete(expiredRevKeys, nil)
	if err != nil {
		slog.Warn("BatchDelete from reverse_nat_map partially failed",
			slog.Int("deleted", deleted),
			slog.Int("total", len(expiredRevKeys)),
			slog.Any("error", err))
	}
}
