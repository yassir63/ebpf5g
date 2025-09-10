#include <linux/bpf.h>
#include <linux/types.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "gtp_latency.h"

#ifndef __always_inline
#define __always_inline inline __attribute__((always_inline))
#endif

#define GTP_PORT 2152
#define MAX_GTP_EXTENSION_HEADERS 4
#define MAX_PACKET_DUMP_LEN 128

struct teid_sampling_state_t {
    __u32 counter;
    __u32 collect_count;
    __u64 latency_acc;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(key_size, sizeof(__u32));  // TEID
    __uint(value_size, sizeof(struct teid_sampling_state_t));
    __uint(max_entries, 1024);
} teid_sample_state_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(__u32));    // TEID
    __uint(value_size, sizeof(__u32));  // Slice ID
    __uint(max_entries, 1024);
} teid_slice_map SEC(".maps");

struct tcp_tracking_t {
    __u64 timestamp_ns;
    __u32 expected_ack;
} __attribute__((packed));

struct full_flow_id_t {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u32 seq;
} __attribute__((packed));

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(struct icmp_id_t));
    __uint(value_size, sizeof(__u64));
    __uint(max_entries, 1024);
} icmp_ts_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(__u32)); // UL TEID
    __uint(value_size, sizeof(__u32)); // DL TEID
    __uint(max_entries, 64);
} teid_pair_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(key_size, sizeof(struct full_flow_id_t));
    __uint(value_size, sizeof(struct tcp_tracking_t));
    __uint(max_entries, 2048);
} ul_flow_ts_map SEC(".maps");


struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(__u32));  // TEID
    __uint(value_size, sizeof(__u8)); // any value, e.g., 1
    __uint(max_entries, 1024);
} tracked_teids SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
    __uint(max_entries, 128);
} teid_events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
    __uint(max_entries, 128);
} latency_events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
    __uint(max_entries, 128);
} flow_events SEC(".maps");

// struct {
//     __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
//     __uint(key_size, sizeof(__u32));
//     __uint(value_size, sizeof(__u32));
//     __uint(max_entries, 128);
// } debug_events SEC(".maps");

// struct {
//     __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
//     __uint(key_size, sizeof(__u32));
//     __uint(value_size, sizeof(__u32));
//     __uint(max_entries, 128);
// } raw_packet_events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u64));
    __uint(max_entries, 1024);
} teid_timestamp_map SEC(".maps");

// static __always_inline void emit_debug_event(struct __sk_buff *skb, __u32 teid, __u8 step, __u32 value) {
//     struct debug_event_t evt = {
//         .teid = teid,
//         .step = step,
//         .value = value,
//     };
//     bpf_perf_event_output(skb, &debug_events, BPF_F_CURRENT_CPU, &evt, sizeof(evt));
// }

// static __always_inline void emit_raw_packet(struct __sk_buff *skb, __u32 teid) {
//     struct raw_packet_t pkt = {};
//     pkt.teid = teid;

//     __u32 len = (__u32) skb->len;
//     if (len == 0)
//         return;

//     if (len > MAX_PACKET_DUMP_LEN)
//         len = MAX_PACKET_DUMP_LEN;

//     pkt.len = (__u16)len;

//     if (bpf_skb_load_bytes(skb, 0, pkt.data, len) < 0)
//         return;

//     bpf_perf_event_output(skb, &raw_packet_events, BPF_F_CURRENT_CPU, &pkt, sizeof(pkt));
// }

static __always_inline int is_gtp_packet(struct __sk_buff *skb) {
    struct ethhdr eth;
    struct iphdr iph;
    struct udphdr udp;

    if (bpf_skb_load_bytes(skb, 0, &eth, sizeof(eth)) < 0)
        return 0;
    if (bpf_ntohs(eth.h_proto) != ETH_P_IP)
        return 0;

    if (bpf_skb_load_bytes(skb, sizeof(eth), &iph, sizeof(iph)) < 0)
        return 0;
    if (iph.protocol != IPPROTO_UDP)
        return 0;

    int ip_header_len = iph.ihl * 4;
    int udp_offset = sizeof(eth) + ip_header_len;
    if (bpf_skb_load_bytes(skb, udp_offset, &udp, sizeof(udp)) < 0)
        return 0;

    __u16 dport = bpf_ntohs(udp.dest);
    __u16 sport = bpf_ntohs(udp.source);

    return dport == GTP_PORT || sport == GTP_PORT;
}

static __always_inline int compute_payload_offset(struct __sk_buff *skb, int gtp_offset, __u8 flags, int *payload_offset, __u32 teid) {
    __u8 has_ext = flags & 0x04;
    __u8 has_seq = flags & 0x02;
    __u8 has_pn  = flags & 0x01;

    int offset = gtp_offset + 8;

    if (has_ext || has_seq || has_pn) {
        offset += 4;
    }

    //emit_debug_event(skb, teid, DEBUG_STEP_GTP_OFFSET, offset);

    if (has_ext) {
        __u8 ext_type = 0;

int ext_header_start = offset - 1;

#pragma unroll
for (int i = 0; i < MAX_GTP_EXTENSION_HEADERS; i++) {
    __u8 ext_type = 0;
    if (bpf_skb_load_bytes(skb, ext_header_start, &ext_type, 1) < 0)
        return -1;
    if (ext_type == 0)
        break;

    __u8 ext_len = 0;
    if (bpf_skb_load_bytes(skb, ext_header_start + 1, &ext_len, 1) < 0)
        return -1;

    // Actual content length:
    int ext_content_len = (ext_len == 1) ? 2 : (ext_len * 4);
    int next_ext_type_offset = ext_header_start + 2 + ext_content_len;

    if (next_ext_type_offset >= skb->len)
        return -1;

    __u8 next_ext_type = 0;
    if (bpf_skb_load_bytes(skb, next_ext_type_offset, &next_ext_type, 1) < 0)
        return -1;

    ext_header_start = next_ext_type_offset + 1;

    if (next_ext_type == 0)
        break;
}

// Final offset is where inner IP starts
offset = ext_header_start;
    }

    *payload_offset = offset;
    return 0;
}

static __always_inline int parse_teid_and_payload_offset(struct __sk_buff *skb, __u32 *teid_out, int *payload_offset) {
    struct ethhdr eth;
    struct iphdr iph;
    struct udphdr udp;

    if (bpf_skb_load_bytes(skb, 0, &eth, sizeof(eth)) < 0)
        return -1;
    if (bpf_ntohs(eth.h_proto) != ETH_P_IP)
        return -1;

    if (bpf_skb_load_bytes(skb, sizeof(eth), &iph, sizeof(iph)) < 0)
        return -1;
    if (iph.protocol != IPPROTO_UDP)
        return -1;

    int ip_header_len = iph.ihl * 4;
    int udp_offset = sizeof(eth) + ip_header_len;
    if (bpf_skb_load_bytes(skb, udp_offset, &udp, sizeof(udp)) < 0)
        return -1;

    if (bpf_ntohs(udp.dest) != GTP_PORT && bpf_ntohs(udp.source) != GTP_PORT)
        return -1;

    int gtp_offset = udp_offset + sizeof(udp);
    unsigned char gtp_hdr[8];
    if (bpf_skb_load_bytes(skb, gtp_offset, gtp_hdr, sizeof(gtp_hdr)) < 0)
        return -1;

    __u8 flags = gtp_hdr[0];
    *teid_out = bpf_ntohl(*((__u32*)&gtp_hdr[4]));

    //emit_debug_event(skb, *teid_out, 1, flags);

    return compute_payload_offset(skb, gtp_offset, flags, payload_offset, *teid_out);
}

static __always_inline void parse_inner_ipv4_flow(struct __sk_buff *skb, int offset, __u32 teid, __u8 direction) {
    __u8 maybe_ip_header = 0;
    if (bpf_skb_load_bytes(skb, offset, &maybe_ip_header, 1) < 0)
        return;

    __u8 version = maybe_ip_header >> 4;
    if (version != 4) {
        struct flow_event_t evt = {
            .teid = teid,
            .proto = 255,
            .direction = direction,
            .timestamp_ns = bpf_ktime_get_ns(),
        };
        bpf_perf_event_output(skb, &flow_events, BPF_F_CURRENT_CPU, &evt, sizeof(evt));
        return;
    }

    struct iphdr inner_iph;
    if (bpf_skb_load_bytes(skb, offset, &inner_iph, sizeof(inner_iph)) < 0)
        return;

    struct flow_event_t evt = {
        .teid = teid,
        .src_ip = inner_iph.saddr,
        .dst_ip = inner_iph.daddr,
        .proto = inner_iph.protocol,
        .src_port = 0,
        .dst_port = 0,
        .direction = direction,
        .timestamp_ns = bpf_ktime_get_ns(),
    };

    int ip_len = inner_iph.ihl * 4;
    int l4_offset = offset + ip_len;

    // Parse L4 ports
    if (evt.proto == IPPROTO_TCP || evt.proto == IPPROTO_UDP) {
        struct { __u16 src, dst; } ports;
        if (bpf_skb_load_bytes(skb, l4_offset, &ports, sizeof(ports)) >= 0) {
            evt.src_port = bpf_ntohs(ports.src);
            evt.dst_port = bpf_ntohs(ports.dst);
        }
    }

    // TCP latency tracking

    if (evt.proto == IPPROTO_TCP) {
        struct {
            __u16 src;
            __u16 dst;
            __u32 seq;
            __u32 ack_seq;
            __u8  offset;
            __u8  flags;
        } tcp_hdr;
    
        if (bpf_skb_load_bytes(skb, l4_offset, &tcp_hdr, sizeof(tcp_hdr)) >= 0) {
            int tcp_hdr_len = (tcp_hdr.offset >> 4) * 4;
            int tcp_payload_offset = l4_offset + tcp_hdr_len;
            int tcp_payload_len = skb->len - tcp_payload_offset;
            if (tcp_payload_len < 0) tcp_payload_len = 0;
    
            if (direction == 1 && (tcp_hdr.flags & 0x10)) {
                struct full_flow_id_t fid = {
                    .src_ip = inner_iph.saddr,
                    .dst_ip = inner_iph.daddr,
                    .src_port = evt.src_port,
                    .dst_port = evt.dst_port,
                    .seq = bpf_ntohl(tcp_hdr.seq) + tcp_payload_len,
                };
    
                struct tcp_tracking_t track = {
                    .timestamp_ns = bpf_ktime_get_ns(),
                    .expected_ack = fid.seq,
                };
    
                bpf_map_update_elem(&ul_flow_ts_map, &fid, &track, BPF_ANY);
            }
    
            //else if (direction == 1 && (tcp_hdr.flags & 0x10)) {
            else if (direction == 0) {
                struct full_flow_id_t reverse_fid = {
                    .src_ip = inner_iph.daddr,
                    .dst_ip = inner_iph.saddr,
                    .src_port = evt.dst_port,
                    .dst_port = evt.src_port,
                    .seq = bpf_ntohl(tcp_hdr.ack_seq),
                };
    
                struct tcp_tracking_t *track = bpf_map_lookup_elem(&ul_flow_ts_map, &reverse_fid);
                if (track && bpf_ntohl(tcp_hdr.ack_seq) == track->expected_ack) {
                    __u64 now = bpf_ktime_get_ns();
                    __u64 delta = now - track->timestamp_ns;
    
     struct latency_event_t latency_evt = {
                        .teid = teid,
                        .latency_ns = delta,
                        .sent_ns =  track->timestamp_ns,
                        .acked_ns = now
                    };
    
    
    struct teid_sampling_state_t *s;
    struct teid_sampling_state_t init_state = { .counter = 1, .collect_count = 0, .latency_acc = 0 };
    
    s = bpf_map_lookup_elem(&teid_sample_state_map, &teid);
    if (!s) {
        bpf_map_update_elem(&teid_sample_state_map, &teid, &init_state, BPF_ANY);
        return;
    }
    
    if (s->collect_count > 0) {
        s->latency_acc += delta;
        s->collect_count++;
    
        if (s->collect_count >= 50) {
            __u64 avg_latency = s->latency_acc / 50;
    
            struct latency_event_t latency_evt = {
                .teid = teid,
                .latency_ns = avg_latency,
                .sent_ns = 0,  // optional — you can use *start_ts if you want
                .acked_ns = 0
            };
    
            bpf_perf_event_output(skb, &latency_events, BPF_F_CURRENT_CPU,
                                  &latency_evt, sizeof(latency_evt));
    
            s->counter = 0;
            s->collect_count = 0;
            s->latency_acc = 0;
        }
    
        return;
    }
    
    s->counter++;
    if (s->counter >= 200) {
        s->collect_count = 1;
        s->latency_acc = delta;
    }
    
    
                    bpf_perf_event_output(skb, &latency_events, BPF_F_CURRENT_CPU,
                                          &latency_evt, sizeof(latency_evt));
    
                    bpf_map_delete_elem(&ul_flow_ts_map, &reverse_fid);
                }
            }
        }
    }
    // ICMP latency tracking
    if (evt.proto == IPPROTO_ICMP) {
struct icmp_echo_hdr_t {
    __u8 type;
    __u8 code;
    __be16 checksum;
    __be16 id;
    __be16 sequence;
};
//emit_debug_event(skb, teid, 100, direction);  // step 100: ICMP seen, value = direction (0=UL, 1=DL)
struct icmp_echo_hdr_t icmp;
        if (bpf_skb_load_bytes(skb, l4_offset, &icmp, sizeof(icmp)) >= 0) {
//emit_debug_event(skb, teid, 210, icmp.type);           // step 210: ICMP type (8=req, 0=reply)
//emit_debug_event(skb, teid, 211, bpf_ntohs(icmp.id));  // step 211: ICMP ID
            struct icmp_id_t key = {
                .src_ip = inner_iph.saddr,
                .dst_ip = inner_iph.daddr,
                .id = bpf_ntohs(icmp.id),
            };

//emit_debug_event(skb, teid, 211, bpf_ntohs(icmp.id));

//emit_debug_event(skb, teid, 210, icmp.type);

if (icmp.type == 8) {
    // Echo Request = uplink
//emit_debug_event(skb, teid, 220, bpf_ntohs(icmp.id));  // step 220: Echo Request stored
    struct icmp_id_t key = {
        .src_ip = inner_iph.saddr,
        .dst_ip = inner_iph.daddr,
        .id = bpf_ntohs(icmp.id),
    };
    __u64 now = bpf_ktime_get_ns();
    bpf_map_update_elem(&icmp_ts_map, &key, &now, BPF_ANY);
}

if (icmp.type == 0) {
    // Echo Reply = downlink
    struct icmp_id_t reverse_key = {
        .src_ip = inner_iph.daddr,
        .dst_ip = inner_iph.saddr,
        .id = bpf_ntohs(icmp.id),
    };
    __u64 *start = bpf_map_lookup_elem(&icmp_ts_map, &reverse_key);
    if (start) {
//emit_debug_event(skb, teid, 230, bpf_ntohs(icmp.id));
        __u64 now = bpf_ktime_get_ns();
        __u64 delta = now - *start;
        struct latency_event_t latency_evt = {
            .teid = teid,
            .latency_ns = delta,
            .sent_ns = *start,
            .acked_ns = now
        };

//emit_debug_event(skb, teid, 231, bpf_ntohs(icmp.id));
        bpf_perf_event_output(skb, &latency_events, BPF_F_CURRENT_CPU, &latency_evt, sizeof(latency_evt));
        bpf_map_delete_elem(&icmp_ts_map, &reverse_key);
    }
}

        }
    }

    // Emit the flow event
    bpf_perf_event_output(skb, &flow_events, BPF_F_CURRENT_CPU, &evt, sizeof(evt));
}


SEC("tc")
int tc_gtp_teid_ingress(struct __sk_buff *skb) {
    if (!is_gtp_packet(skb))
        return TC_ACT_PIPE;

    __u32 teid = 0;
    int payload_offset;

    if (parse_teid_and_payload_offset(skb, &teid, &payload_offset) < 0) {
        if (teid == 0) teid = 0xdeadbeef;

        __u64 now = bpf_ktime_get_ns();
        bpf_map_update_elem(&teid_timestamp_map, &teid, &now, BPF_ANY);

        struct flow_event_t failed_evt = {
            .teid = teid,
            .src_ip = 0,
            .dst_ip = 0,
            .src_port = 0,
            .dst_port = 0,
            .proto = 255,
            .direction = 0,
        };
        bpf_perf_event_output(skb, &flow_events, BPF_F_CURRENT_CPU, &failed_evt, sizeof(failed_evt));
        return TC_ACT_PIPE;
    }

    __u64 now = bpf_ktime_get_ns();
    bpf_map_update_elem(&teid_timestamp_map, &teid, &now, BPF_ANY);

    struct teid_event_t evt = { .teid = teid, .source = 0 };
    bpf_perf_event_output(skb, &teid_events, BPF_F_CURRENT_CPU, &evt, sizeof(evt));

    parse_inner_ipv4_flow(skb, payload_offset, teid, 0);
    return TC_ACT_PIPE;
}

SEC("tc")
int tc_gtp_teid_egress(struct __sk_buff *skb) {
    if (!is_gtp_packet(skb))
        return TC_ACT_PIPE;

    __u32 teid = 0;
    int payload_offset;

    if (parse_teid_and_payload_offset(skb, &teid, &payload_offset) < 0) {
        if (teid == 0) teid = 0xdeadbeef;

        __u64 now = bpf_ktime_get_ns();
        __u64 *start_ts = bpf_map_lookup_elem(&teid_timestamp_map, &teid);
        if (start_ts) {
            __u64 delta = now - *start_ts;
            struct latency_event_t latency_evt = { .teid = teid, .latency_ns = delta, .sent_ns =*start_ts, .acked_ns=now };
            bpf_perf_event_output(skb, &latency_events, BPF_F_CURRENT_CPU, &latency_evt, sizeof(latency_evt));
            bpf_map_delete_elem(&teid_timestamp_map, &teid);
        }

        struct flow_event_t failed_evt = {
            .teid = teid,
            .src_ip = 0,
            .dst_ip = 0,
            .src_port = 0,
            .dst_port = 0,
            .proto = 255,
            .direction = 1,
        };
        bpf_perf_event_output(skb, &flow_events, BPF_F_CURRENT_CPU, &failed_evt, sizeof(failed_evt));
        return TC_ACT_PIPE;
    }

    struct teid_event_t evt = { .teid = teid, .source = 1 };
    bpf_perf_event_output(skb, &teid_events, BPF_F_CURRENT_CPU, &evt, sizeof(evt));

    __u64 now = bpf_ktime_get_ns();
    __u64 *start_ts = bpf_map_lookup_elem(&teid_timestamp_map, &teid);
    if (start_ts) {
        __u64 delta = now - *start_ts;
        struct latency_event_t latency_evt = { .teid = teid, .latency_ns = delta, .sent_ns =*start_ts, .acked_ns=now };
        bpf_perf_event_output(skb, &latency_events, BPF_F_CURRENT_CPU, &latency_evt, sizeof(latency_evt));
        bpf_map_delete_elem(&teid_timestamp_map, &teid);
    }

    parse_inner_ipv4_flow(skb, payload_offset, teid, 1);
    return TC_ACT_PIPE;
}



char LICENSE[] SEC("license") = "GPL";
