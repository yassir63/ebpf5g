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
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u32); // TEID
    __type(value, struct teid_stats_t);
} teid_throughput_map SEC(".maps");


struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(__u32)); // TEID
    __uint(value_size, sizeof(__u32)); // Slice ID
    __uint(max_entries, 1024);
} teid_slice_map2 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(__u32)); // TEID
    __uint(value_size, sizeof(__u8)); // dummy presence flag
    __uint(max_entries, 1024);
} tracked_teids SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(__u32)); // TEID
    __uint(value_size, sizeof(struct teid_stats_t));
    __uint(max_entries, 1024);
} teid_stats_map SEC(".maps");

static __always_inline int extract_teid(struct __sk_buff *skb, __u32 *teid_out) {
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

    *teid_out = bpf_ntohl(*((__u32*)&gtp_hdr[4]));
    return 0;
}

static __always_inline int handle_gtp_packet(struct __sk_buff *skb) {
    __u32 teid;
    if (extract_teid(skb, &teid) < 0)
        return TC_ACT_PIPE;

    __u8 *present = bpf_map_lookup_elem(&tracked_teids, &teid);
    if (!present)
        return TC_ACT_PIPE;

    struct teid_stats_t *stats = bpf_map_lookup_elem(&teid_stats_map, &teid);
    if (!stats) {
        struct teid_stats_t init = { .packet_count = 1, .byte_count = skb->len };
        bpf_map_update_elem(&teid_stats_map, &teid, &init, BPF_ANY);
    } else {
        __sync_fetch_and_add(&stats->packet_count, 1);
        __sync_fetch_and_add(&stats->byte_count, skb->len);
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
