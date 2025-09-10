#include <stdio.h>
#include <signal.h>
#include <unistd.h>
#include <stdlib.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "gtp_teid_tc.skel.h"

static volatile sig_atomic_t exiting = 0;

static void handle_event(void *ctx, int cpu, void *data, __u32 size) {
    __u32 teid = *(__u32 *)data;
    printf("Captured TEID: 0x%08x\n", teid);
    FILE *log = fopen("teid_log.txt", "a");
    if (log) {
        fprintf(log, "0x%08x\n", teid);
        fclose(log);
    }
}

static void sig_handler(int signo) {
    exiting = 1;
}

int main(int argc, char **argv) {
    const char *iface = argc > 1 ? argv[1] : "n3";
    struct gtp_teid_tc_bpf *skel;
struct bpf_tc_hook hook = {
    .sz = sizeof(struct bpf_tc_hook),
    .ifindex = if_nametoindex(iface),
    .attach_point = BPF_TC_INGRESS,
};

struct bpf_tc_opts opts = {
    .sz = sizeof(struct bpf_tc_opts),
    .handle = 1,
    .priority = 1,
};
    if (hook.ifindex == 0) {
        fprintf(stderr, "Could not find interface: %s\n", iface);
        return 1;
    }

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    skel = gtp_teid_tc_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "Failed to load BPF skeleton\n");
        return 1;
    }

opts.prog_fd = bpf_program__fd(skel->progs.tc_gtp_teid_extract);
if (bpf_tc_attach(&hook, &opts)) {
    fprintf(stderr, "Failed to attach BPF to tc ingress\n");
    return 1;
}


    struct perf_buffer *pb = NULL;
    pb = perf_buffer__new(bpf_map__fd(skel->maps.teid_events), 8, handle_event, NULL, NULL, NULL);
    if (!pb) {
        fprintf(stderr, "Failed to open perf buffer\n");
        return 1;
    }

    printf("Listening for TEIDs on %s (CTRL+C to exit)...\n", iface);
    while (!exiting) {
        perf_buffer__poll(pb, 100);
    }

    bpf_tc_detach(&hook, &opts);
    gtp_teid_tc_bpf__destroy(skel);
    return 0;
}
