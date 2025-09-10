#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define GTP_PORT 2152

struct teid_event_t {
    __u32 teid;
};

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
    __uint(max_entries, 128);
} teid_events SEC(".maps");

SEC("classifier")
int tc_gtp_teid_extract(struct __sk_buff *skb) {
    struct ethhdr eth;
    struct iphdr iph;
    struct udphdr udp;
    unsigned char gtp_hdr[8];

    // Load Ethernet header
    if (bpf_skb_load_bytes(skb, 0, &eth, sizeof(eth)) < 0)
        return TC_ACT_PIPE;

    if (bpf_ntohs(eth.h_proto) != ETH_P_IP)
        return TC_ACT_PIPE;

    // Load IP header
    if (bpf_skb_load_bytes(skb, sizeof(eth), &iph, sizeof(iph)) < 0)
        return TC_ACT_PIPE;

    if (iph.protocol != IPPROTO_UDP)
        return TC_ACT_PIPE;

    int ip_header_len = iph.ihl * 4;

    // Load UDP header
    if (bpf_skb_load_bytes(skb, sizeof(eth) + ip_header_len, &udp, sizeof(udp)) < 0)
        return TC_ACT_PIPE;

    if (bpf_ntohs(udp.dest) != GTP_PORT)
        return TC_ACT_PIPE;

    // Load GTP header
    int gtp_offset = sizeof(eth) + ip_header_len + sizeof(udp);
    if (bpf_skb_load_bytes(skb, gtp_offset, gtp_hdr, sizeof(gtp_hdr)) < 0)
        return TC_ACT_PIPE;

    // Extract TEID
    __u32 teid = ((__u32)gtp_hdr[4] << 24) |
                 ((__u32)gtp_hdr[5] << 16) |
                 ((__u32)gtp_hdr[6] << 8)  |
                 ((__u32)gtp_hdr[7]);

    struct teid_event_t evt = { .teid = teid };
    bpf_perf_event_output(skb, &teid_events, BPF_F_CURRENT_CPU, &evt, sizeof(evt));

    return TC_ACT_PIPE;
}

char LICENSE[] SEC("license") = "GPL";
