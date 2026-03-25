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

	// Phase 1: Collect expired forward (conntrack) entries and their paired reverse keys.
	expiredForwardKeys, pairedRevKeys, err := gc.collectExpiredKeys(ctx, now)
	if err != nil {
		return err
	}

	// Phase 2: Collect expired reverse entries independently.
	// This catches orphaned reverse entries whose forward (conntrack) entry was
	// already evicted by LRU — without this pass, those entries would accumulate
	// until the reverse map fills up and LRU evicts them itself.
	expiredOrphanRevKeys, err := gc.collectExpiredReverseKeys(ctx, now)
	if err != nil {
		return err
	}

	// Merge and deduplicate reverse keys to avoid double-delete noise in logs.
	allRevKeys := mergeUniqueKeys(pairedRevKeys, expiredOrphanRevKeys)

	if len(expiredForwardKeys) == 0 && len(allRevKeys) == 0 {
		slog.Debug("Garbage collection completed, no sessions evicted")
		return nil
	}

	// Phase 3: Batch delete expired entries.
	gc.batchDeleteForward(expiredForwardKeys)
	gc.batchDeleteReverse(allRevKeys)

	slog.Info("Garbage collection completed",
		slog.Int("evicted_forward", len(expiredForwardKeys)),
		slog.Int("evicted_reverse", len(allRevKeys)))
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

			// Guard against uint64 underflow: clock skew or stale timestamps
			// could cause entry.LastSeen > now, yielding a huge age value.
			if entry.LastSeen > now {
				continue
			}
			age := now - entry.LastSeen
			if age > uint64(timeout.Nanoseconds()) {
				slog.Debug("Marking expired session for eviction",
					slog.Any("key", key),
					slog.Duration("age", time.Duration(age)))

				expiredKeys = append(expiredKeys, key)
				// Construct reverse key matching BPF's reverse_key construction
				revKey := bpf.NatNatKey{
					SrcIp:    key.DstIp,
					DstIp:    entry.TranslatedIp,
					Protocol: key.Protocol,
				}
				if key.Protocol == syscall.IPPROTO_ICMP {
					// ICMP reverse keys use allocated_port for both src and dst
					revKey.SrcPort = entry.TranslatedPort
					revKey.DstPort = entry.TranslatedPort
				} else {
					revKey.SrcPort = key.DstPort
					revKey.DstPort = entry.TranslatedPort
				}
				expiredRevKeys = append(expiredRevKeys, revKey)
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

// collectExpiredReverseKeys scans the reverse_nat_map independently and returns
// entries whose last_seen timestamp has exceeded the session timeout.
// This catches orphaned entries whose forward (conntrack) counterpart was evicted by LRU.
func (gc *GarbageCollector) collectExpiredReverseKeys(ctx context.Context, now uint64) ([]bpf.NatNatKey, error) {
	var expiredKeys []bpf.NatNatKey

	var cursor ebpf.MapBatchCursor
	keys := make([]bpf.NatNatKey, defaultBatchSize)
	values := make([]bpf.NatNatEntry, defaultBatchSize)

	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		count, err := gc.objects.ReverseNatMap.BatchLookup(&cursor, keys, values, nil)

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

			if entry.LastSeen > now {
				continue
			}
			age := now - entry.LastSeen
			if age > uint64(timeout.Nanoseconds()) {
				expiredKeys = append(expiredKeys, key)
			}
		}

		if errors.Is(err, ebpf.ErrKeyNotExist) {
			break
		}
		if err != nil {
			return nil, err
		}
	}

	return expiredKeys, nil
}

// mergeUniqueKeys returns a slice containing all keys from a, plus any keys from b
// not already present in a. This prevents double-delete log noise when a key appears
// in both the forward-paired set and the independent reverse scan.
func mergeUniqueKeys(a, b []bpf.NatNatKey) []bpf.NatNatKey {
	if len(b) == 0 {
		return a
	}
	seen := make(map[bpf.NatNatKey]struct{}, len(a))
	for _, k := range a {
		seen[k] = struct{}{}
	}
	result := append([]bpf.NatNatKey{}, a...)
	for _, k := range b {
		if _, ok := seen[k]; !ok {
			result = append(result, k)
		}
	}
	return result
}

func (gc *GarbageCollector) batchDeleteForward(expiredKeys []bpf.NatNatKey) {
	if len(expiredKeys) == 0 {
		return
	}
	deleted, err := gc.objects.ConntrackMap.BatchDelete(expiredKeys, nil)
	if err != nil {
		slog.Warn("BatchDelete from conntrack_map partially failed",
			slog.Int("deleted", deleted),
			slog.Int("total", len(expiredKeys)),
			slog.Any("error", err))
	}
}

func (gc *GarbageCollector) batchDeleteReverse(revKeys []bpf.NatNatKey) {
	if len(revKeys) == 0 {
		return
	}
	deleted, err := gc.objects.ReverseNatMap.BatchDelete(revKeys, nil)
	if err != nil {
		slog.Warn("BatchDelete from reverse_nat_map partially failed",
			slog.Int("deleted", deleted),
			slog.Int("total", len(revKeys)),
			slog.Any("error", err))
	}
}
