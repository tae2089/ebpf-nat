#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>
#include "nat.h"

// Connection tracking map for SNAT
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, struct nat_key);
    __type(value, struct nat_entry);
} conntrack_map SEC(".maps");

SEC("tc")
int tc_nat_prog(struct __sk_buff *skb) {
    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
