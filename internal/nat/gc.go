package nat

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/tae2089/ebpf-nat/internal/bpf"
)

// sessionLimitWarningsTotal는 per-source 세션 수 경고 카운터다.
// prometheus 대신 atomic 카운터를 사용하여 의존성 최소화.
var sessionLimitWarningsTotal sessionLimitCounter

type sessionLimitCounter struct {
	count uint64
}

func (c *sessionLimitCounter) Inc() {
	atomic.AddUint64(&c.count, 1)
}

func (c *sessionLimitCounter) Load() uint64 {
	return atomic.LoadUint64(&c.count)
}

const defaultBatchSize = 256

type GarbageCollector struct {
	objects              *bpf.NatObjects
	tcpTimeout           time.Duration
	tcpClosingTimeout    time.Duration
	tcpSynSentTimeout    time.Duration // TCP SYN-SENT(half-open) 세션 타임아웃
	udpTimeout           time.Duration
	maxSessionsPerSource uint32 // 0 = 비활성 (per-source 세션 수 경고 임계값)
}

func NewGarbageCollector(objs *bpf.NatObjects, tcpTimeout, udpTimeout time.Duration) *GarbageCollector {
	return &GarbageCollector{
		objects:              objs,
		tcpTimeout:           tcpTimeout,
		tcpClosingTimeout:    2 * time.Minute,
		tcpSynSentTimeout:    75 * time.Second, // RFC 793 SYN 재전송 타임아웃 기준
		udpTimeout:           udpTimeout,
		maxSessionsPerSource: 0, // 기본: 비활성
	}
}

func (gc *GarbageCollector) RunOnce(ctx context.Context, now uint64) error {
	slog.Debug("Starting NAT map garbage collection")

	// Phase 1: Collect expired forward (conntrack) entries and their paired reverse keys.
	// Also collect per-source session counts if monitoring is enabled.
	expiredForwardKeys, pairedRevKeys, sourceCount, err := gc.collectExpiredKeys(ctx, now)
	if err != nil {
		return err
	}

	// Phase 1b: Per-source 세션 수 초과 경고
	if gc.maxSessionsPerSource > 0 {
		for srcIP, count := range sourceCount {
			if uint32(count) > gc.maxSessionsPerSource {
				slog.Warn("Source IP exceeds session limit",
					slog.String("src_ip", uint32ToIPStr(srcIP)),
					slog.Int("session_count", count),
					slog.Uint64("max_sessions_per_source", uint64(gc.maxSessionsPerSource)))
				sessionLimitWarningsTotal.Inc()
			}
		}
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

// uint32ToIPStr는 uint32 IP를 점 표기법 문자열로 변환한다 (BigEndian 기준).
func uint32ToIPStr(ip uint32) string {
	return fmt.Sprintf("%d.%d.%d.%d",
		byte(ip>>24), byte(ip>>16), byte(ip>>8), byte(ip))
}

func (gc *GarbageCollector) collectExpiredKeys(ctx context.Context, now uint64) ([]bpf.NatNatKey, []bpf.NatNatKey, map[uint32]int, error) {
	var expiredKeys []bpf.NatNatKey
	var expiredRevKeys []bpf.NatNatKey

	// per-source 세션 카운터 (maxSessionsPerSource가 0이면 수집하지 않음)
	var sourceCount map[uint32]int
	if gc.maxSessionsPerSource > 0 {
		sourceCount = make(map[uint32]int)
	}

	var cursor ebpf.MapBatchCursor
	keys := make([]bpf.NatNatKey, defaultBatchSize)
	values := make([]bpf.NatNatEntry, defaultBatchSize)

	for {
		select {
		case <-ctx.Done():
			return nil, nil, nil, ctx.Err()
		default:
		}

		count, err := gc.objects.ConntrackMap.BatchLookup(&cursor, keys, values, nil)

		for i := range count {
			key := keys[i]
			entry := values[i]

			// per-source 카운터 수집
			if sourceCount != nil {
				sourceCount[key.SrcIp]++
			}

			var timeout time.Duration
			if entry.State == NatStateClosing {
				timeout = gc.tcpClosingTimeout
			} else if key.Protocol == syscall.IPPROTO_TCP && entry.State == NatStateActive && gc.objects.ReverseNatMap != nil {
				// TCP ACTIVE 상태인데 reverse_nat_map에 엔트리가 없으면 SYN-SENT(half-open)로 간주한다.
				// 이 경우 tcpSynSentTimeout(기본 75초)을 적용하여 포트 점유를 방지한다.
				revKey := bpf.NatNatKey{
					SrcIp:    key.DstIp,
					DstIp:    entry.TranslatedIp,
					SrcPort:  key.DstPort,
					DstPort:  entry.TranslatedPort,
					Protocol: key.Protocol,
				}
				var revEntry bpf.NatNatEntry
				if lookupErr := gc.objects.ReverseNatMap.Lookup(revKey, &revEntry); lookupErr != nil {
					// reverse 엔트리 없음 → half-open 세션
					timeout = gc.tcpSynSentTimeout
					slog.Debug("TCP session has no reverse entry, applying syn-sent timeout",
						slog.Any("key", key),
						slog.Duration("timeout", timeout))
				} else {
					timeout = gc.tcpTimeout
				}
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
			return nil, nil, nil, err
		}
	}

	return expiredKeys, expiredRevKeys, sourceCount, nil
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

		for i := range count {
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
