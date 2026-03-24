#ifndef __NAT_H__
#define __NAT_H__

#include <linux/types.h>

#define EPHEMERAL_PORT_START 32768
#define EPHEMERAL_PORT_END   60999
#define PORT_SCAN_LIMIT      128

struct nat_key {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8  protocol;
    __u8  pad[3]; // Padding for 8-byte alignment
} __attribute__((aligned(8)));

struct nat_entry {
    __u32 translated_ip;
    __u16 translated_port;
    __u8  state; // NAT_STATE_ACTIVE, NAT_STATE_CLOSING
    __u8  pad;
    __u64 last_seen; // For session aging
} __attribute__((aligned(8)));

#define NAT_STATE_ACTIVE  0
#define NAT_STATE_CLOSING 1

struct snat_config {
    __u32 external_ip;
    __u32 internal_net;
    __u32 internal_mask;
    __u16 max_mss;
    __u16 pad;
} __attribute__((aligned(8)));


// Checksum helpers
static __always_inline void update_tcp_csum(struct __sk_buff *skb, __u32 tcp_off, __be32 old_ip, __be32 new_ip, __be16 old_port, __be16 new_port) {
    bpf_l4_csum_replace(skb, tcp_off + offsetof(struct tcphdr, check), old_ip, new_ip, BPF_F_PSEUDO_HDR | sizeof(new_ip));
    bpf_l4_csum_replace(skb, tcp_off + offsetof(struct tcphdr, check), old_port, new_port, sizeof(new_port));
}

static __always_inline void update_udp_csum(struct __sk_buff *skb, __u32 udp_off, __be32 old_ip, __be32 new_ip, __be16 old_port, __be16 new_port) {
    bpf_l4_csum_replace(skb, udp_off + offsetof(struct udphdr, check), old_ip, new_ip, BPF_F_PSEUDO_HDR | sizeof(new_ip));
    bpf_l4_csum_replace(skb, udp_off + offsetof(struct udphdr, check), old_port, new_port, sizeof(new_port));
}

static __always_inline void update_ip_csum(struct __sk_buff *skb, __u32 ip_off, __be32 old_ip, __be32 new_ip) {
    bpf_l3_csum_replace(skb, ip_off + offsetof(struct iphdr, check), old_ip, new_ip, sizeof(new_ip));
}

#define DIRECTION_INGRESS 0
#define DIRECTION_EGRESS  1

#define ACTION_TRANSLATED 0
#define ACTION_DROPPED    1
#define ACTION_PASSED      2
#define ACTION_ALLOC_FAIL 3
#define ACTION_MAP_UPDATE_FAIL 4

struct metrics_key {
    __u8 protocol;
    __u8 direction;
    __u8 action;
};

struct metrics_value {
    __u64 packets;
    __u64 bytes;
};

// Minimal ICMP header for eBPF
struct icmphdr {
    __u8		type;
    __u8		code;
    __sum16		checksum;
    union {
        struct {
            __be16	id;
            __be16	sequence;
        } echo;
        __be32	gateway;
        struct {
            __be16	__unused;
            __be16	mtu;
        } frag;
    } un;
};

#define ICMP_ECHOREPLY		0	/* Echo Reply			*/
#define ICMP_DEST_UNREACH	3	/* Destination Unreachable	*/
#define ICMP_ECHO		8	/* Echo Request			*/
#define ICMP_TIME_EXCEEDED	11	/* Time Exceeded		*/

#endif /* __NAT_H__ */
