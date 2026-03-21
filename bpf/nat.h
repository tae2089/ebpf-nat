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

#endif /* __NAT_H__ */
