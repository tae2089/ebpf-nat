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

static __always_inline int apply_nat(struct __sk_buff *skb, struct nat_entry *entry, bool is_snat) {
    void *data_end = (void *)(long)skb->data_end;
    void *data     = (void *)(long)skb->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return TC_ACT_OK;

    struct iphdr *iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > data_end)
        return TC_ACT_OK;

    __be32 old_ip, new_ip;
    __be16 old_port, new_port;
    __u8 protocol = iph->protocol;

    if (is_snat) {
        old_ip = iph->saddr;
        new_ip = entry->translated_ip;
    } else {
        old_ip = iph->daddr;
        new_ip = entry->translated_ip;
    }
    new_port = entry->translated_port;

    if (protocol == IPPROTO_TCP) {
        struct tcphdr *th = (void *)(iph + 1);
        if ((void *)(th + 1) > data_end)
            return TC_ACT_OK;

        if (is_snat) {
            old_port = th->source;
            th->source = new_port;
            iph->saddr = new_ip;
        } else {
            old_port = th->dest;
            th->dest = new_port;
            iph->daddr = new_ip;
        }
        bpf_l3_csum_replace(skb, offsetof(struct iphdr, check), old_ip, new_ip, sizeof(new_ip));
        bpf_l4_csum_replace(skb, offsetof(struct tcphdr, check), old_ip, new_ip, BPF_F_PSEUDO_HDR | sizeof(new_ip));
        bpf_l4_csum_replace(skb, offsetof(struct tcphdr, check), old_port, new_port, sizeof(new_port));
    } else if (protocol == IPPROTO_UDP) {
        struct udphdr *uh = (void *)(iph + 1);
        if ((void *)(uh + 1) > data_end)
            return TC_ACT_OK;

        if (is_snat) {
            old_port = uh->source;
            uh->source = new_port;
            iph->saddr = new_ip;
        } else {
            old_port = uh->dest;
            uh->dest = new_port;
            iph->daddr = new_ip;
        }
        bpf_l3_csum_replace(skb, offsetof(struct iphdr, check), old_ip, new_ip, sizeof(new_ip));
        bpf_l4_csum_replace(skb, offsetof(struct udphdr, check), old_ip, new_ip, BPF_F_PSEUDO_HDR | sizeof(new_ip));
        bpf_l4_csum_replace(skb, offsetof(struct udphdr, check), old_port, new_port, sizeof(new_port));
    } else if (protocol == IPPROTO_ICMP) {
        struct icmphdr *ih = (void *)(iph + 1);
        if ((void *)(ih + 1) > data_end)
            return TC_ACT_OK;

        // Echo Request (is_snat) or Echo Reply (not is_snat)
        if (ih->type == ICMP_ECHO || ih->type == ICMP_ECHOREPLY) {
            old_port = ih->un.echo.id;
            ih->un.echo.id = new_port;
            
            if (is_snat) {
                iph->saddr = new_ip;
            } else {
                iph->daddr = new_ip;
            }
            
            bpf_l3_csum_replace(skb, offsetof(struct iphdr, check), old_ip, new_ip, sizeof(new_ip));
            // ICMP doesn't use pseudo-header for checksum
            bpf_l4_csum_replace(skb, offsetof(struct icmphdr, checksum), old_port, new_port, sizeof(new_port));
        }
    }

    return TC_ACT_OK;
}

SEC("tc")
int tc_nat_prog(struct __sk_buff *skb) {
    void *data_end = (void *)(long)skb->data_end;
    void *data     = (void *)(long)skb->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return TC_ACT_OK;

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return TC_ACT_OK;

    struct iphdr *iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > data_end)
        return TC_ACT_OK;

    struct nat_key key = {0};
    key.src_ip   = iph->saddr;
    key.dst_ip   = iph->daddr;
    key.protocol = iph->protocol;

    if (iph->protocol == IPPROTO_TCP) {
        struct tcphdr *th = (void *)(iph + 1);
        if ((void *)(th + 1) > data_end)
            return TC_ACT_OK;
        key.src_port = th->source;
        key.dst_port = th->dest;
    } else if (iph->protocol == IPPROTO_UDP) {
        struct udphdr *uh = (void *)(iph + 1);
        if ((void *)(uh + 1) > data_end)
            return TC_ACT_OK;
        key.src_port = uh->source;
        key.dst_port = uh->dest;
    } else if (iph->protocol == IPPROTO_ICMP) {
        struct icmphdr *ih = (void *)(iph + 1);
        if ((void *)(ih + 1) > data_end)
            return TC_ACT_OK;
        
        if (ih->type == ICMP_ECHO || ih->type == ICMP_ECHOREPLY) {
            key.src_port = ih->un.echo.id;
            key.dst_port = ih->un.echo.id; // ICMP doesn't have dst_port, use ID for both
        } else {
            // Error messages (Type 3, 11 etc) will be handled in Phase 2
            return TC_ACT_OK;
        }
    } else {
        return TC_ACT_OK;
    }

    // 1. Check existing conntrack session (Forward: Original -> Translated)
    struct nat_entry *entry = bpf_map_lookup_elem(&conntrack_map, &key);
    if (entry) {
        entry->last_seen = bpf_ktime_get_ns();
        return apply_nat(skb, entry, true);
    }

    // 2. Check reverse NAT session (Return: Translated -> Original)
    entry = bpf_map_lookup_elem(&reverse_nat_map, &key);
    if (entry) {
        entry->last_seen = bpf_ktime_get_ns();
        return apply_nat(skb, entry, false);
    }

    // 3. Static DNAT rules
    entry = bpf_map_lookup_elem(&dnat_rules, &key);
    if (entry) {
        entry->last_seen = bpf_ktime_get_ns();
        return apply_nat(skb, entry, false);
    }

    // 4. Dynamic SNAT (Masquerading)
    __u32 zero = 0;
    struct snat_config *cfg = bpf_map_lookup_elem(&snat_config_map, &zero);
    if (!cfg || cfg->external_ip == 0) {
        return TC_ACT_OK;
    }

    // Boundary check again before accessing iph
    if ((void *)(iph + 1) > data_end)
        return TC_ACT_OK;

    // Basic heuristic: SNAT if source IP is different from external IP
    if (iph->saddr == cfg->external_ip) {
        return TC_ACT_OK;
    }

    // Port/ID Allocation
    __u32 hash = bpf_get_prandom_u32();
    __u32 start_port = EPHEMERAL_PORT_START + (hash % (EPHEMERAL_PORT_END - EPHEMERAL_PORT_START + 1));
    __u16 allocated_port = 0;

    #pragma unroll
    for (int i = 0; i < PORT_SCAN_LIMIT; i++) {
        __u32 test_port_32 = EPHEMERAL_PORT_START + ((start_port - EPHEMERAL_PORT_START + i) % (EPHEMERAL_PORT_END - EPHEMERAL_PORT_START + 1));
        __u16 test_port = (__u16)test_port_32;

        // Key for return traffic to check collision
        struct nat_key rev_check_key = {0};
        rev_check_key.src_ip = iph->daddr;
        rev_check_key.dst_ip = cfg->external_ip;
        
        if (iph->protocol == IPPROTO_ICMP) {
            rev_check_key.src_port = bpf_htons(test_port); // Expected ID in reply
            rev_check_key.dst_port = bpf_htons(test_port);
        } else {
            rev_check_key.src_port = key.dst_port;
            rev_check_key.dst_port = bpf_htons(test_port);
        }
        rev_check_key.protocol = iph->protocol;

        if (!bpf_map_lookup_elem(&reverse_nat_map, &rev_check_key)) {
            allocated_port = bpf_htons(test_port);
            break;
        }
    }

    if (allocated_port == 0) {
        return TC_ACT_OK; // No port/ID available
    }

    // Create conntrack entries
    struct nat_entry forward_entry = {
        .translated_ip = cfg->external_ip,
        .translated_port = allocated_port,
        .last_seen = bpf_ktime_get_ns(),
    };
    bpf_map_update_elem(&conntrack_map, &key, &forward_entry, BPF_ANY);

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
    bpf_map_update_elem(&reverse_nat_map, &reverse_key, &reverse_entry, BPF_ANY);

    return apply_nat(skb, &forward_entry, true);
}

char _license[] SEC("license") = "GPL";
