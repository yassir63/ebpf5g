#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/pkt_cls.h>

#define GTP_PORT 2152

struct teid_stats_t {
    __u64 packet_count;
    __u64 byte_count;
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(struct teid_stats_t));
    __uint(max_entries, 1024);
} teid_stats_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
    __uint(max_entries, 1024);
} teid_slice_map2 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u8));
    __uint(max_entries, 1024);
} tracked_teids SEC(".maps");

static __always_inline int fast_extract_teid(struct __sk_buff *skb, __u32 *teid_out) {
    __u8 ip_first_byte;
    if (bpf_skb_load_bytes(skb, ETH_HLEN, &ip_first_byte, 1) < 0)
        return -1;

    int ip_header_len = (ip_first_byte & 0x0F) * 4;
    int udp_offset = ETH_HLEN + ip_header_len;
    int gtp_offset = udp_offset + sizeof(struct udphdr);

    if (gtp_offset + 8 > skb->len)
        return -1;

    unsigned char gtp_hdr[8];
    if (bpf_skb_load_bytes(skb, gtp_offset, gtp_hdr, sizeof(gtp_hdr)) < 0)
        return -1;

    *teid_out = bpf_ntohl(*((__u32*)&gtp_hdr[4]));
    return 0;
}

static __always_inline int handle_gtp_packet(struct __sk_buff *skb) {
    __u32 teid;
    if (fast_extract_teid(skb, &teid) < 0)
        return TC_ACT_PIPE;

    __u8 *present = bpf_map_lookup_elem(&tracked_teids, &teid);
    if (!present)
        return TC_ACT_PIPE;

    struct teid_stats_t *stats = bpf_map_lookup_elem(&teid_stats_map, &teid);
    if (!stats) {
        struct teid_stats_t init = { .packet_count = 1, .byte_count = skb->len };
        bpf_map_update_elem(&teid_stats_map, &teid, &init, BPF_ANY);
    } else {
        stats->packet_count += 1;
        stats->byte_count += skb->len;
    }

    return TC_ACT_PIPE;
}

SEC("tc")
int tc_gtp_ingress(struct __sk_buff *skb) {
    return handle_gtp_packet(skb);
}

SEC("tc")
int tc_gtp_egress(struct __sk_buff *skb) {
    return handle_gtp_packet(skb);
}

char LICENSE[] SEC("license") = "GPL";
