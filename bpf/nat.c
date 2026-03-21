#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <linux/pkt_cls.h>
#include <stddef.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "nat.h"

// Connection tracking map for SNAT/DNAT
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
    } else {
        return TC_ACT_OK;
    }

    // 1. Check existing conntrack session
    struct nat_entry *entry = bpf_map_lookup_elem(&conntrack_map, &key);
    
    // 2. If no session, check DNAT rules
    if (!entry) {
        entry = bpf_map_lookup_elem(&dnat_rules, &key);
    }

    if (!entry) {
        return TC_ACT_OK;
    }

    entry->last_seen = bpf_ktime_get_ns();

    // Determine if it's SNAT (source change) or DNAT (destination change)
    // For simplicity, we use entry type or flags later. 
    // Here we check if the translated info targets the source or destination.
    // In a real NAT, we would have explicit Ingress/Egress logic.
    
    // Boundary check again
    if ((void *)(iph + 1) > data_end)
        return TC_ACT_OK;

    // Apply transformation
    // NOTE: This implementation currently handles both SNAT/DNAT by replacing
    // source for egress and destination for ingress based on map lookup.
    // We will refine this in later iterations.
    
    // For skeleton, we assume it's DNAT if it's Ingress and SNAT if it's Egress.
    // Here we just apply the map entry directly to Dst for demonstration of DNAT logic.
    
    __be32 old_ip = iph->daddr;
    __be32 new_ip = entry->translated_ip;
    __be16 new_port = entry->translated_port;

    iph->daddr = new_ip;
    bpf_l3_csum_replace(skb, offsetof(struct iphdr, check), old_ip, new_ip, sizeof(new_ip));

    if (iph->protocol == IPPROTO_TCP) {
        struct tcphdr *th = (void *)(iph + 1);
        if ((void *)(th + 1) <= data_end) {
            __be16 old_port = th->dest;
            th->dest = new_port;
            bpf_l4_csum_replace(skb, offsetof(struct tcphdr, check), old_ip, new_ip, BPF_F_PSEUDO_HDR | sizeof(new_ip));
            bpf_l4_csum_replace(skb, offsetof(struct tcphdr, check), old_port, new_port, sizeof(new_port));
        }
    } else if (iph->protocol == IPPROTO_UDP) {
        struct udphdr *uh = (void *)(iph + 1);
        if ((void *)(uh + 1) <= data_end) {
            __be16 old_port = uh->dest;
            uh->dest = new_port;
            bpf_l4_csum_replace(skb, offsetof(struct udphdr, check), old_ip, new_ip, BPF_F_PSEUDO_HDR | sizeof(new_ip));
            bpf_l4_csum_replace(skb, offsetof(struct udphdr, check), old_port, new_port, sizeof(new_port));
        }
    }

    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
