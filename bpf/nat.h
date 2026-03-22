#ifndef __NAT_H__
#define __NAT_H__

#include <linux/types.h>

#define EPHEMERAL_PORT_START 32768
#define EPHEMERAL_PORT_END   60999
#define PORT_SCAN_LIMIT      64

struct nat_key {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8  protocol;
};

struct nat_entry {
    __u32 translated_ip;
    __u16 translated_port;
    __u64 last_seen; // For session aging
};

struct snat_config {
    __u32 external_ip;
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
