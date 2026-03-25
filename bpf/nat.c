#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <linux/pkt_cls.h>
#include <stddef.h>
#include <stdbool.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "nat.h"

// Connection tracking map for SNAT (Original -> Translated)
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, struct nat_key);
    __type(value, struct nat_entry);
} conntrack_map SEC(".maps");

// Static DNAT map for port forwarding
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, struct nat_key);
    __type(value, struct nat_entry);
} dnat_rules SEC(".maps");

// Reverse NAT map for return traffic and collision check (Translated -> Original)
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, struct nat_key);
    __type(value, struct nat_entry);
} reverse_nat_map SEC(".maps");

// Global SNAT configuration
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct snat_config);
} snat_config_map SEC(".maps");

// Global metrics map
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __uint(max_entries, 1024);
    __type(key, struct metrics_key);
    __type(value, struct metrics_value);
} metrics_map SEC(".maps");

static __always_inline void update_metrics(__u8 protocol, __u8 direction, __u8 action, __u32 bytes) {
    // C-1: zero-initialization으로 패딩 바이트가 가비지 값을 갖지 않도록 한다.
    // 컴파일러가 추가한 패딩 바이트가 초기화되지 않으면 동일한 논리 키가
    // 다른 패딩 값으로 인해 서로 다른 맵 엔트리를 참조할 수 있다.
    struct metrics_key key = {};
    key.protocol = protocol;
    key.direction = direction;
    key.action = action;
    struct metrics_value *val = bpf_map_lookup_elem(&metrics_map, &key);
    if (val) {
        val->packets++;
        val->bytes += bytes;
    } else {
        struct metrics_value new_val = { .packets = 1, .bytes = bytes };
        bpf_map_update_elem(&metrics_map, &key, &new_val, BPF_ANY);
    }
}

static __always_inline void clamp_mss(struct __sk_buff *skb, struct tcphdr *th, __u16 max_mss, __u32 l4_off) {
    if (max_mss == 0) return;
    if (!(th->syn)) return;

    void *data_end = (void *)(long)skb->data_end;
    __u8 *opt = (__u8 *)(th + 1);

    // Only check the first option for simplicity and verifier satisfaction
    if ((void *)(opt + 4) > data_end) return;

    if (opt[0] == 2 && opt[1] == 4) { // MSS kind and length
        __be16 *mss_p = (__be16 *)(opt + 2);
        __be16 old_mss_be = *mss_p;
        __u16 mss = bpf_ntohs(old_mss_be);
        if (mss > max_mss) {
            __be16 new_mss_be = bpf_htons(max_mss);
            *mss_p = new_mss_be;
            // Update TCP checksum incrementally
            // Offset: l4_off + 16 (TCP Checksum)
            bpf_l4_csum_replace(skb, l4_off + 16, old_mss_be, new_mss_be, sizeof(new_mss_be));
        }
    }
}

static __always_inline int apply_nat(struct __sk_buff *skb, struct nat_entry *entry, bool is_snat, __u32 l3_off, __u32 l4_off) {
    void *data_end = (void *)(long)skb->data_end;
    void *data     = (void *)(long)skb->data;

    struct iphdr *iph = data + l3_off;
    if ((void *)(iph + 1) > data_end) return TC_ACT_OK;

    __be32 old_ip, new_ip;
    __be16 old_port_be, new_port_be;
    __u8 protocol = iph->protocol;

    if (is_snat) {
        old_ip = iph->saddr;
        new_ip = entry->translated_ip;
    } else {
        old_ip = iph->daddr;
        new_ip = entry->translated_ip;
    }

    new_port_be = bpf_htons(entry->translated_port);

    if (protocol == IPPROTO_TCP) {
        struct tcphdr *th = data + l4_off;
        if ((void *)(th + 1) > data_end) return TC_ACT_OK;

        if (is_snat) {
            old_port_be = th->source;
            th->source = new_port_be;
            iph->saddr = new_ip;
        } else {
            old_port_be = th->dest;
            th->dest = new_port_be;
            iph->daddr = new_ip;
        }
        update_ip_csum(skb, l3_off, old_ip, new_ip);
        update_tcp_csum(skb, l4_off, old_ip, new_ip, old_port_be, new_port_be);
    } else if (protocol == IPPROTO_UDP) {
        struct udphdr *uh = data + l4_off;
        if ((void *)(uh + 1) > data_end) return TC_ACT_OK;

        if (is_snat) {
            old_port_be = uh->source;
            uh->source = new_port_be;
            iph->saddr = new_ip;
        } else {
            old_port_be = uh->dest;
            uh->dest = new_port_be;
            iph->daddr = new_ip;
        }
        update_ip_csum(skb, l3_off, old_ip, new_ip);
        update_udp_csum(skb, l4_off, old_ip, new_ip, old_port_be, new_port_be);
    } else if (protocol == IPPROTO_ICMP) {
        struct icmphdr *ih = data + l4_off;
        if ((void *)(ih + 1) > data_end) return TC_ACT_OK;

        if (ih->type == ICMP_ECHO || ih->type == ICMP_ECHOREPLY) {
            old_port_be = ih->un.echo.id;
            ih->un.echo.id = new_port_be;
            if (is_snat) iph->saddr = new_ip;
            else iph->daddr = new_ip;

            update_ip_csum(skb, l3_off, old_ip, new_ip);
            bpf_l4_csum_replace(skb, l4_off + offsetof(struct icmphdr, checksum), old_port_be, new_port_be, sizeof(new_port_be));
        }
    }

    return TC_ACT_OK;
}

static __always_inline int apply_nat_icmp_error(struct __sk_buff *skb, struct nat_entry *entry, __u32 l3_off) {
    void *data_end = (void *)(long)skb->data_end;
    void *data     = (void *)(long)skb->data;

    // Minimum requirement: L3(20) + ICMP(8) + InnerIP(20) + InnerL4(8) = 56 bytes
    if (data + l3_off + 56 > data_end) return TC_ACT_OK;

    struct iphdr *outer_iph = data + l3_off;
    struct icmphdr *ih = data + l3_off + 20;
    struct iphdr *inner_iph = data + l3_off + 28;

    // C-2: inner IP 헤더의 IHL을 검증한다.
    // IHL > 5이면 IP 옵션이 포함되어 포트 오프셋(l3_off+48)이 틀려지므로 패킷을 통과시킨다.
    if (inner_iph->ihl != 5) return TC_ACT_OK;

    // C-3: inner L4 프로토콜 검증
    // ICMP 에러 메시지의 inner 패킷은 TCP 또는 UDP여야 한다.
    // 다른 프로토콜의 경우 포트 필드가 없으므로 수정 없이 통과시킨다.
    if (inner_iph->protocol != IPPROTO_TCP && inner_iph->protocol != IPPROTO_UDP) {
        return TC_ACT_OK;
    }

    __be32 old_inner_src = inner_iph->saddr;
    __be32 new_inner_src = entry->translated_ip;
    __be16 old_inner_port_be = 0;
    __be16 new_inner_port_be = bpf_htons(entry->translated_port);

    // Only access first 8 bytes of inner L4 header (common for TCP/UDP in ICMP errors)
    __be16 *inner_ports = data + l3_off + 48;
    old_inner_port_be = inner_ports[0]; // Source port is first 2 bytes
    inner_ports[0] = new_inner_port_be;

    inner_iph->saddr = new_inner_src;
    __be32 old_outer_dst = outer_iph->daddr;
    __be32 new_outer_dst = entry->translated_ip;
    outer_iph->daddr = new_outer_dst;

    // Checksums
    update_ip_csum(skb, l3_off + 28, old_inner_src, new_inner_src); // Inner IP
    update_ip_csum(skb, l3_off, old_outer_dst, new_outer_dst); // Outer IP

    // ICMP checksum covers the entire payload (inner IP header + inner L4 header).
    // The inner saddr change and the resulting inner IP checksum change cancel each
    // other in one's complement arithmetic, so only the port change needs adjustment.
    if (old_inner_port_be != new_inner_port_be) {
        bpf_l4_csum_replace(skb, l3_off + 20 + offsetof(struct icmphdr, checksum), old_inner_port_be, new_inner_port_be, sizeof(new_inner_port_be));
    }

    return TC_ACT_OK;
}

static __always_inline int handle_nat(struct __sk_buff *skb, bool is_ingress) {
    void *data_end = (void *)(long)skb->data_end;
    void *data     = (void *)(long)skb->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return TC_ACT_OK;

    __u16 eth_proto = eth->h_proto;
    __u32 l3_off = sizeof(struct ethhdr);

    // Support VLAN tags (802.1Q)
    // Note: QinQ (802.1AD) outer tag is detected but only one tag layer is stripped.
    // Full QinQ support would add ~30 BPF instructions, pushing near verifier complexity limits.
    if (eth_proto == bpf_htons(ETH_P_8021Q) || eth_proto == bpf_htons(ETH_P_8021AD)) {
        struct {
            __be16 tci;
            __be16 next_proto;
        } *vlan_hdr = data + l3_off;

        if ((void *)(vlan_hdr + 1) > data_end) return TC_ACT_OK;
        eth_proto = vlan_hdr->next_proto;
        l3_off += 4;
    }

    if (eth_proto != bpf_htons(ETH_P_IP)) {
        return TC_ACT_OK;
    }

    struct iphdr *iph = data + l3_off;
    if ((void *)(iph + 1) > data_end) return TC_ACT_OK;

    // Security: Validate IP version to reject malformed packets
    if (iph->version != 4) return TC_ACT_OK;

    // Validate IP header length (IHL)
    __u8 ihl = iph->ihl;
    if (ihl < 5 || ihl > 15) return TC_ACT_OK;

    // Skip packets with IP options — variable IHL breaks BPF verifier's
    // ability to track packet offsets. Standard packets (99%+) have IHL=5.
    if (ihl != 5) return TC_ACT_OK;

    // Security: Skip IP fragments — they lack complete L4 headers
    // frag_offset != 0: non-first fragment (no L4 header)
    // more_frags (MF bit): first fragment with more fragments following
    // Both cases must be skipped to prevent incomplete L4 header processing.
#ifndef IP_MF
#define IP_MF 0x2000
#endif
    __u16 frag_info = bpf_ntohs(iph->frag_off);
    __u16 frag_offset = frag_info & 0x1FFF;
    bool more_frags = (frag_info & IP_MF) != 0;
    if (frag_offset != 0 || more_frags) return TC_ACT_OK;

    // Validate IP total length is sane (at least 20 bytes for standard header)
    __u16 tot_len = bpf_ntohs(iph->tot_len);
    if (tot_len < 20) return TC_ACT_OK;

    // Fixed L4 offset: IHL is always 5 (20 bytes) after the check above
    __u32 l4_off = l3_off + sizeof(struct iphdr);

    struct nat_key key = {0};
    key.src_ip   = iph->saddr;
    key.dst_ip   = iph->daddr;
    key.protocol = iph->protocol;

    bool is_tcp_fin_rst = false;

    if (iph->protocol == IPPROTO_TCP) {
        struct tcphdr *th = data + l4_off;
        if ((void *)(th + 1) > data_end) return TC_ACT_OK;
        key.src_port = bpf_ntohs(th->source);
        key.dst_port = bpf_ntohs(th->dest);
        if (th->fin || th->rst) is_tcp_fin_rst = true;
    } else if (iph->protocol == IPPROTO_UDP) {
        struct udphdr *uh = data + l4_off;
        if ((void *)(uh + 1) > data_end) return TC_ACT_OK;
        key.src_port = bpf_ntohs(uh->source);
        key.dst_port = bpf_ntohs(uh->dest);
    } else if (iph->protocol == IPPROTO_ICMP) {
        struct icmphdr *ih = data + l4_off;
        if ((void *)(ih + 1) > data_end) return TC_ACT_OK;
        
        if (ih->type == ICMP_ECHO || ih->type == ICMP_ECHOREPLY) {
            key.src_port = bpf_ntohs(ih->un.echo.id);
            key.dst_port = bpf_ntohs(ih->un.echo.id);
        } else if (ih->type == ICMP_DEST_UNREACH || ih->type == ICMP_TIME_EXCEEDED) {
            // Inner IP starts after ICMP header (8 bytes)
            {
                struct iphdr *inner_iph = (void *)(ih + 1);
                if ((void *)(inner_iph + 1) > data_end) return TC_ACT_OK;

                struct nat_key lookup_key = {0};
                lookup_key.src_ip = inner_iph->daddr;
                lookup_key.dst_ip = inner_iph->saddr;
                lookup_key.protocol = inner_iph->protocol;

                if ((void *)(data + l4_off + 32) > data_end) return TC_ACT_OK;
                __be16 *inner_ports = (void *)(data + l4_off + 28);
                lookup_key.src_port = bpf_ntohs(inner_ports[1]);
                lookup_key.dst_port = bpf_ntohs(inner_ports[0]);

                if (is_ingress) {
                    struct nat_entry *inner_entry = bpf_map_lookup_elem(&reverse_nat_map, &lookup_key);
                    if (inner_entry) {
                        update_metrics(iph->protocol, DIRECTION_INGRESS, ACTION_TRANSLATED, skb->len);
                        return apply_nat_icmp_error(skb, inner_entry, l3_off);
                    }
                } else {
                    // Egress ICMP Error: check DNAT rules then conntrack
                    struct nat_entry *inner_entry = bpf_map_lookup_elem(&dnat_rules, &lookup_key);
                    if (inner_entry) {
                        update_metrics(iph->protocol, DIRECTION_EGRESS, ACTION_TRANSLATED, skb->len);
                        return apply_nat_icmp_error(skb, inner_entry, l3_off);
                    }

                    inner_entry = bpf_map_lookup_elem(&conntrack_map, &lookup_key);
                    if (inner_entry) {
                        update_metrics(iph->protocol, DIRECTION_EGRESS, ACTION_TRANSLATED, skb->len);
                        return apply_nat_icmp_error(skb, inner_entry, l3_off);
                    }
                }
            }
            return TC_ACT_OK;
        } else {
            return TC_ACT_OK;
        }
    } else {
        return TC_ACT_OK;
    }

    __u32 zero = 0;
    struct snat_config *cfg = bpf_map_lookup_elem(&snat_config_map, &zero);

    if (is_ingress) {
        struct nat_entry *entry = bpf_map_lookup_elem(&reverse_nat_map, &key);
        if (entry) {
            entry->last_seen = bpf_ktime_get_ns();
            if (is_tcp_fin_rst) {
                entry->state = NAT_STATE_CLOSING;
            }
            update_metrics(key.protocol, DIRECTION_INGRESS, ACTION_TRANSLATED, skb->len);
            
            // Re-validate pointers for the verifier
            data     = (void *)(long)skb->data;
            data_end = (void *)(long)skb->data_end;
            struct iphdr *iph2 = (void *)(data + l3_off);
            if ((void *)(iph2 + 1) > data_end) return TC_ACT_OK;

            if (iph2->protocol == IPPROTO_TCP && cfg) {
                struct tcphdr *th = (void *)(data + l4_off);
                if ((void *)(th + 1) > data_end) return TC_ACT_OK;
                clamp_mss(skb, th, cfg->max_mss, l4_off);
            }

            return apply_nat(skb, entry, false, l3_off, l4_off);
        }

        entry = bpf_map_lookup_elem(&dnat_rules, &key);
        if (entry) {
            entry->last_seen = bpf_ktime_get_ns();
            update_metrics(key.protocol, DIRECTION_INGRESS, ACTION_TRANSLATED, skb->len);

            data     = (void *)(long)skb->data;
            data_end = (void *)(long)skb->data_end;
            struct iphdr *iph2 = (void *)(data + l3_off);
            if ((void *)(iph2 + 1) > data_end) return TC_ACT_OK;
            if (iph2->protocol == IPPROTO_TCP && cfg) {
                struct tcphdr *th = (void *)(data + l4_off);
                if ((void *)(th + 1) > data_end) return TC_ACT_OK;
                clamp_mss(skb, th, cfg->max_mss, l4_off);
            }

            return apply_nat(skb, entry, false, l3_off, l4_off);
        }
    } else {
        struct nat_entry *entry = bpf_map_lookup_elem(&conntrack_map, &key);
        if (entry) {
            entry->last_seen = bpf_ktime_get_ns();
            if (is_tcp_fin_rst) {
                entry->state = NAT_STATE_CLOSING;
            }
            update_metrics(key.protocol, DIRECTION_EGRESS, ACTION_TRANSLATED, skb->len);

            data     = (void *)(long)skb->data;
            data_end = (void *)(long)skb->data_end;
            struct iphdr *iph2 = (void *)(data + l3_off);
            if ((void *)(iph2 + 1) > data_end) return TC_ACT_OK;
            if (iph2->protocol == IPPROTO_TCP && cfg) {
                struct tcphdr *th = (void *)(data + l4_off);
                if ((void *)(th + 1) > data_end) return TC_ACT_OK;
                clamp_mss(skb, th, cfg->max_mss, l4_off);
            }

            return apply_nat(skb, entry, true, l3_off, l4_off);
        }

        if (!cfg || cfg->external_ip == 0) return TC_ACT_OK;
        if (iph->saddr == cfg->external_ip) return TC_ACT_OK;

        // Security: Anti-Spoofing (Source Address Verification)
        // If internal_net is configured, only allow packets from that subnet
        if (cfg->internal_mask != 0) {
            if ((iph->saddr & cfg->internal_mask) != cfg->internal_net) {
                update_metrics(iph->protocol, DIRECTION_EGRESS, ACTION_DROPPED, skb->len);
                return TC_ACT_SHOT;
            }
        }

        // Security: For TCP, only create sessions on SYN packets
        if (iph->protocol == IPPROTO_TCP) {
            struct tcphdr *th = (void *)(data + l4_off);
            if ((void *)(th + 1) > data_end) return TC_ACT_OK;
            if (!(th->syn) || th->ack) {
                // Not a SYN packet or has ACK (not a new connection attempt)
                return TC_ACT_OK;
            }
        }

        // Dynamic SNAT allocation logic with power-of-two randomized probe
        __u32 hash = bpf_get_prandom_u32();
        __u16 allocated_port = 0;

        // 1. Try 2 random probes first
        #pragma unroll
        for (int i = 0; i < 2; i++) {
            __u32 probe_port_32 = EPHEMERAL_PORT_START + (bpf_get_prandom_u32() % (EPHEMERAL_PORT_END - EPHEMERAL_PORT_START + 1));
            __u16 test_port = (__u16)probe_port_32;

            struct nat_key rev_check_key = {0};
            rev_check_key.src_ip = iph->daddr;
            rev_check_key.dst_ip = cfg->external_ip;
            if (iph->protocol == IPPROTO_ICMP) {
                rev_check_key.src_port = test_port;
                rev_check_key.dst_port = test_port;
            } else {
                rev_check_key.src_port = key.dst_port;
                rev_check_key.dst_port = test_port;
            }
            rev_check_key.protocol = iph->protocol;

            if (!bpf_map_lookup_elem(&reverse_nat_map, &rev_check_key)) {
                allocated_port = test_port;
                break;
            }
        }

        // 2. Fallback to linear scan if random probes failed
        if (allocated_port == 0) {
            __u32 start_port = EPHEMERAL_PORT_START + (hash % (EPHEMERAL_PORT_END - EPHEMERAL_PORT_START + 1));
            #pragma unroll
            for (int i = 0; i < PORT_SCAN_LIMIT; i++) {
                __u32 test_port_32 = EPHEMERAL_PORT_START + ((start_port - EPHEMERAL_PORT_START + i) % (EPHEMERAL_PORT_END - EPHEMERAL_PORT_START + 1));
                __u16 test_port = (__u16)test_port_32;

                struct nat_key rev_check_key = {0};
                rev_check_key.src_ip = iph->daddr;
                rev_check_key.dst_ip = cfg->external_ip;
                if (iph->protocol == IPPROTO_ICMP) {
                    rev_check_key.src_port = test_port;
                    rev_check_key.dst_port = test_port;
                } else {
                    rev_check_key.src_port = key.dst_port;
                    rev_check_key.dst_port = test_port;
                }
                rev_check_key.protocol = iph->protocol;

                if (!bpf_map_lookup_elem(&reverse_nat_map, &rev_check_key)) {
                    allocated_port = test_port;
                    break;
                }
            }
        }

        if (allocated_port == 0) {
            update_metrics(iph->protocol, DIRECTION_EGRESS, ACTION_ALLOC_FAIL, skb->len);
            return TC_ACT_SHOT;
        }

        struct nat_entry forward_entry = {
            .translated_ip = cfg->external_ip,
            .translated_port = allocated_port,
            .last_seen = bpf_ktime_get_ns(),
        };
        long ret = bpf_map_update_elem(&conntrack_map, &key, &forward_entry, BPF_ANY);
        if (ret != 0) {
            update_metrics(iph->protocol, DIRECTION_EGRESS, ACTION_MAP_UPDATE_FAIL, skb->len);
            return TC_ACT_SHOT;
        }

        struct nat_key reverse_key = {0};
        reverse_key.src_ip = iph->daddr;
        reverse_key.dst_ip = cfg->external_ip;
        if (iph->protocol == IPPROTO_ICMP) {
            reverse_key.src_port = allocated_port;
            reverse_key.dst_port = allocated_port;
        } else {
            reverse_key.src_port = key.dst_port;
            reverse_key.dst_port = allocated_port;
        }
        reverse_key.protocol = iph->protocol;

        struct nat_entry reverse_entry = {
            .translated_ip = iph->saddr,
            .translated_port = key.src_port,
            .last_seen = bpf_ktime_get_ns(),
        };
        // Use BPF_NOEXIST to atomically detect per-CPU port allocation races.
        // If another CPU already inserted this reverse key (same port), fail fast
        // and roll back the forward entry rather than silently overwriting it.
        ret = bpf_map_update_elem(&reverse_nat_map, &reverse_key, &reverse_entry, BPF_NOEXIST);
        if (ret != 0) {
            bpf_map_delete_elem(&conntrack_map, &key);
            update_metrics(iph->protocol, DIRECTION_EGRESS, ACTION_MAP_UPDATE_FAIL, skb->len);
            return TC_ACT_SHOT;
        }

        update_metrics(iph->protocol, DIRECTION_EGRESS, ACTION_TRANSLATED, skb->len);
        
        data     = (void *)(long)skb->data;
        data_end = (void *)(long)skb->data_end;
        struct iphdr *iph3 = (void *)(data + l3_off);
        if ((void *)(iph3 + 1) > data_end) return TC_ACT_OK;
        if (iph3->protocol == IPPROTO_TCP) {
            struct tcphdr *th_final = (void *)(data + l4_off);
            if ((void *)(th_final + 1) > data_end) return TC_ACT_OK;
            clamp_mss(skb, th_final, cfg->max_mss, l4_off);
        }
        
        return apply_nat(skb, &forward_entry, true, l3_off, l4_off);
    }

    return TC_ACT_OK;
}

SEC("tc/ingress")
int tc_nat_ingress(struct __sk_buff *skb) {
    return handle_nat(skb, true);
}

SEC("tc/egress")
int tc_nat_egress(struct __sk_buff *skb) {
    return handle_nat(skb, false);
}

char _license[] SEC("license") = "GPL";
