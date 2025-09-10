#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <string.h>
#include <net/if.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "gtp_throughput.skel.h"
#include <time.h>
#include <sys/socket.h>
#include <sys/un.h>

#define MAX_TEIDS 1024
struct teid_cache_t {
    __u64 last_bytes;
    __u64 last_seen_ns;
};

struct teid_cache_t cache[MAX_TEIDS];
struct teid_stats_t {
    __u64 packet_count;
    __u64 byte_count;
};

static volatile sig_atomic_t exiting = 0;

static int map_fd_slice = -1;
static const char *iface = NULL;
static int priority = 1;
static int ingress_handle = 1;
static int egress_handle = 2;
static int sockfd = -1;
static struct gtp_throughput_bpf *skel = NULL;
static struct bpf_tc_opts opts_ingress = {}, opts_egress = {};
static struct bpf_tc_hook hook = { .sz = sizeof(struct bpf_tc_hook) };

void cleanup() {
    fprintf(stderr, "\n🧼 Cleaning up eBPF filters on interface %s...\n", iface);

    hook.ifindex = if_nametoindex(iface);

    hook.attach_point = BPF_TC_INGRESS;
    if (bpf_tc_detach(&hook, &opts_ingress) != 0) {
        fprintf(stderr, "⚠️ bpf_tc_detach failed on ingress. Trying tc fallback...\n");
        char cmd[128];
        snprintf(cmd, sizeof(cmd), "tc filter del dev %s ingress prio %u", iface, priority);
        system(cmd);
    }

    hook.attach_point = BPF_TC_EGRESS;
    if (bpf_tc_detach(&hook, &opts_egress) != 0) {
        fprintf(stderr, "⚠️ bpf_tc_detach failed on egress. Trying tc fallback...\n");
        char cmd[128];
        snprintf(cmd, sizeof(cmd), "tc filter del dev %s egress prio %u", iface, priority);
        system(cmd);
    }

    if (skel) {
        gtp_throughput_bpf__destroy(skel);
        skel = NULL;
    }

    if (sockfd > 0) {
        close(sockfd);
        sockfd = -1;
    }

    fprintf(stderr, "✅ Cleanup complete.\n");
    exit(0);
}

static void sig_handler(int signo) {
    exiting = 1;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <interface> [--ingress-handle N] [--egress-handle N] [--priority N] <TEIDs...>\n", argv[0]);
        return 1;
    }

    iface = argv[1];
    int arg_idx = 2;

    while (arg_idx < argc && argv[arg_idx][0] == '-') {
        if (strcmp(argv[arg_idx], "--ingress-handle") == 0) {
            ingress_handle = strtoul(argv[++arg_idx], NULL, 0);
        } else if (strcmp(argv[arg_idx], "--egress-handle") == 0) {
            egress_handle = strtoul(argv[++arg_idx], NULL, 0);
        } else if (strcmp(argv[arg_idx], "--priority") == 0) {
            priority = strtoul(argv[++arg_idx], NULL, 0);
        } else {
            fprintf(stderr, "Unknown option: %s\n", argv[arg_idx]);
            return 1;
        }
        arg_idx++;
    }

    signal(SIGINT, cleanup);
    signal(SIGTERM, cleanup);

    skel = gtp_throughput_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "Failed to load BPF skeleton\n");
        return 1;
    }

    map_fd_slice = bpf_map__fd(skel->maps.teid_slice_map2);

    for (int i = arg_idx; i < argc; i++) {
        char *arg = argv[i];
        char *sep = strchr(arg, ':');
        char *at = strchr(arg, '@');
        __u32 slice_id = 0;

        if (at) {
            *at = '\0';
            slice_id = strtoul(at + 1, NULL, 0);
        }

        if (sep) {
            *sep = '\0';
            __u32 ul = strtoul(arg, NULL, 0);
            __u32 dl = strtoul(sep + 1, NULL, 0);
            __u8 one = 1;
            bpf_map_update_elem(bpf_map__fd(skel->maps.tracked_teids), &ul, &one, BPF_ANY);
            bpf_map_update_elem(bpf_map__fd(skel->maps.tracked_teids), &dl, &one, BPF_ANY);
            if (slice_id) {
                bpf_map_update_elem(map_fd_slice, &ul, &slice_id, BPF_ANY);
                bpf_map_update_elem(map_fd_slice, &dl, &slice_id, BPF_ANY);
            }
        } else {
            __u32 teid = strtoul(arg, NULL, 0);
            __u8 one = 1;
            bpf_map_update_elem(bpf_map__fd(skel->maps.tracked_teids), &teid, &one, BPF_ANY);
            if (slice_id)
                bpf_map_update_elem(map_fd_slice, &teid, &slice_id, BPF_ANY);
        }
    }

    hook.ifindex = if_nametoindex(iface);

    opts_ingress.sz = sizeof(struct bpf_tc_opts);
    opts_ingress.handle = ingress_handle;
    opts_ingress.priority = priority;
    opts_ingress.prog_fd = bpf_program__fd(skel->progs.tc_gtp_ingress);
    hook.attach_point = BPF_TC_INGRESS;
    bpf_tc_attach(&hook, &opts_ingress);

    opts_egress.sz = sizeof(struct bpf_tc_opts);
    opts_egress.handle = egress_handle;
    opts_egress.priority = priority;
    opts_egress.prog_fd = bpf_program__fd(skel->progs.tc_gtp_egress);
    hook.attach_point = BPF_TC_EGRESS;
    bpf_tc_attach(&hook, &opts_egress);

    struct sockaddr_un addr = { .sun_family = AF_UNIX };
    strncpy(addr.sun_path, "/tmp/gtp_throughput.sock", sizeof(addr.sun_path) - 1);
    sockfd = socket(AF_UNIX, SOCK_STREAM, 0);

    int attempts = 0;
    while (connect(sockfd, (struct sockaddr*)&addr, sizeof(addr)) < 0 && attempts++ < 10) {
        perror("connect()");
        sleep(1);
    }

    int stats_fd = bpf_map__fd(skel->maps.teid_stats_map);

    while (!exiting) {
        sleep(1);
        __u32 key = 0, next_key;
        struct teid_stats_t stats;

        while (bpf_map_get_next_key(stats_fd, &key, &next_key) == 0) {
            if (bpf_map_lookup_elem(stats_fd, &next_key, &stats) == 0) {
                __u32 slice_id = 0;
                bpf_map_lookup_elem(map_fd_slice, &next_key, &slice_id);
                struct teid_cache_t *entry = &cache[next_key % MAX_TEIDS];
                __u64 now = (uint64_t)time(NULL);
                __u64 delta_bytes = stats.byte_count - entry->last_bytes;
                __u64 bps = delta_bytes * 8;
                entry->last_bytes = stats.byte_count;

                char msg[512];
                snprintf(msg, sizeof(msg),
                         "{\"teid\": %u, \"packets\": %llu, \"bytes\": %llu, \"bitrate\": %llu, \"slice\": %u}",
                         next_key, stats.packet_count, stats.byte_count, bps, slice_id);
                send(sockfd, msg, strlen(msg), 0);
            }
            key = next_key;
        }
    }

    cleanup(); // in case we reach here without signal
    return 0;
}
