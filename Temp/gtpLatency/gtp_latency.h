#ifndef __GTP_LATENCY_H__
#define __GTP_LATENCY_H__

#include <linux/types.h>

enum debug_step_t {
    DEBUG_STEP_GTP_FLAGS            = 1,
    DEBUG_STEP_GTP_OFFSET           = 2,
    DEBUG_STEP_EXT_START            = 10,
    DEBUG_STEP_EXT_TYPE             = 20,
    DEBUG_STEP_EXT_LEN              = 30,
    DEBUG_STEP_EXT_NEXT_TYPE        = 40,
    DEBUG_STEP_EXT_END              = 250,
    DEBUG_STEP_PAYLOAD_OFFSET      = 201,
    DEBUG_STEP_PAYLOAD_BYTE        = 200,
    DEBUG_STEP_IP_VERSION          = 102,
    DEBUG_STEP_EXT_LOAD_TYPE_FAIL  = 251,
    DEBUG_STEP_EXT_LOAD_LEN_FAIL   = 252,
    DEBUG_STEP_EXT_LOAD_NEXT_FAIL  = 253,
    DEBUG_STEP_EXT_BOUNDS_EXCEEDED = 254,
    DEBUG_STEP_PAYLOAD_PARSE_FAIL  = 255,
};

struct icmp_id_t {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 id;      // ICMP identifier (from Echo Request/Reply)
} __attribute__((packed));

struct flow_id_t {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
};

struct teid_event_t {
    __u32 teid;
    __u8 source; // 0 = ingress, 1 = egress
};

struct latency_event_t {
    __u32 teid;          // GTP Tunnel ID (optional for filtering)
    __u64 latency_ns;    // Measured latency (ns)

    __u64 sent_ns;       // Timestamp when uplink packet was seen
    __u64 acked_ns;      // Timestamp when matching ACK was seen
};
#define MAX_PACKET_DUMP_LEN 128

struct raw_packet_t {
    __u32 teid;
    __u16 len;
    __u8 data[MAX_PACKET_DUMP_LEN];
};

struct debug_event_t {
    __u32 teid;
    __u8  step;
    __u32 value;
};

struct flow_event_t {
    __u32 teid;
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8 proto;
    __u8 direction;
    __u64 timestamp_ns; // Add this
};
#endif // __GTP_LATENCY_H__