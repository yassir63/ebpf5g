#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <string.h>
#include <net/if.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "gtp_latency.skel.h"
#include "gtp_latency.h"
#include <json-c/json.h>
#include <sys/un.h>
#include <sys/socket.h>

static volatile sig_atomic_t exiting = 0;
static int map_fd_teid_slice = -1;

/* globals so cleanup() can detach correctly */
static struct gtp_latency_bpf *skel = NULL;
static struct bpf_tc_hook hook = { .sz = sizeof(struct bpf_tc_hook) };
static struct bpf_tc_opts opts_ingress = {};
static struct bpf_tc_opts opts_egress = {};
static const char *iface = NULL;
static int priority = 1;

static int libbpf_prn(enum libbpf_print_level lvl, const char *fmt, va_list args) {
    return vfprintf(stderr, fmt, args);
}

static void cleanup() {
    fprintf(stderr, "\n🧼 Cleaning up eBPF filters on interface %s...\n", iface ? iface : "(unknown)");

    if (iface) {
        hook.ifindex = if_nametoindex(iface);

        hook.attach_point = BPF_TC_INGRESS;
        if (bpf_tc_detach(&hook, &opts_ingress) != 0) {
            fprintf(stderr, "⚠️ bpf_tc_detach failed on ingress. Trying tc fallback...\n");
            char cmd[128];
            snprintf(cmd, sizeof(cmd), "tc filter del dev %s ingress prio %u", iface, priority);
            (void)system(cmd);
        }

        hook.attach_point = BPF_TC_EGRESS;
        if (bpf_tc_detach(&hook, &opts_egress) != 0) {
            fprintf(stderr, "⚠️ bpf_tc_detach failed on egress. Trying tc fallback...\n");
            char cmd[128];
            snprintf(cmd, sizeof(cmd), "tc filter del dev %s egress prio %u", iface, priority);
            (void)system(cmd);
        }
    }

    if (skel) {
        gtp_latency_bpf__destroy(skel);
        skel = NULL;
    }

    fprintf(stderr, "✅ Cleanup complete.\n");
}

static void sig_handler(int signo) {
    exiting = 1;
    cleanup();
}

static void handle_latency_event(void *ctx, int cpu, void *data, __u32 size) {
    const struct latency_event_t *evt = data;
    __u32 slice_id = 0;

    (void)bpf_map_lookup_elem(map_fd_teid_slice, &evt->teid, &slice_id);

    json_object *root = json_object_new_object();

    char teid_str[12];
    snprintf(teid_str, sizeof(teid_str), "0x%08x", evt->teid);
    json_object_object_add(root, "teid", json_object_new_string(teid_str));
    json_object_object_add(root, "latency_ns", json_object_new_int64(evt->latency_ns));
    json_object_object_add(root, "slice", json_object_new_int(slice_id));

    int sock = socket(AF_UNIX, SOCK_DGRAM, 0);
    if (sock >= 0) {
        struct sockaddr_un addr = { .sun_family = AF_UNIX };
        strcpy(addr.sun_path, "/tmp/gtp_latency.sock");
        const char *payload = json_object_to_json_string(root);
        sendto(sock, payload, strlen(payload), 0, (struct sockaddr *)&addr, sizeof(addr));
        close(sock);
    }

    json_object_put(root);
}

int main(int argc, char **argv) {
    libbpf_set_print(libbpf_prn);

    /* allow locking BPF objects without memlock errors */
    struct rlimit rl = { RLIM_INFINITY, RLIM_INFINITY };
    setrlimit(RLIMIT_MEMLOCK, &rl);

    iface = (argc > 1) ? argv[1] : "n3";
    int prio = 1, hndl = 1;
    int argi = 2;

    while (argi < argc) {
        if (strcmp(argv[argi], "--prio") == 0 && argi + 1 < argc) {
            prio = atoi(argv[++argi]);
        } else if (strcmp(argv[argi], "--handle") == 0 && argi + 1 < argc) {
            hndl = atoi(argv[++argi]);
        } else {
            break;
        }
        argi++;
    }
    priority = prio;

    hook.ifindex = if_nametoindex(iface);
    if (hook.ifindex == 0) {
        fprintf(stderr, "Could not find interface: %s\n", iface);
        return 1;
    }

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    /* open+load */
    skel = gtp_latency_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "Failed to load BPF skeleton\n");
        return 1;
    }

    map_fd_teid_slice = bpf_map__fd(skel->maps.teid_slice_map);

    /* parse TEID args: TEIDUL:TEIDDL[@slice] or single TEID[@slice] */
    for (int i = argi; i < argc; i++) {
        char *arg = argv[i];
        char *at = strchr(arg, '@');
        char *colon = strchr(arg, ':');

        __u32 slice_id = 0;

        if (at) {
            *at = '\0';  // split off @slice
            slice_id = strtoul(at + 1, NULL, 0);
        }

        if (colon) {
            *colon = '\0';
            __u32 ul = strtoul(arg, NULL, 0);
            __u32 dl = strtoul(colon + 1, NULL, 0);

            bpf_map_update_elem(bpf_map__fd(skel->maps.teid_pair_map), &ul, &dl, BPF_ANY);
            printf("Tracking UL TEID 0x%08x → DL TEID 0x%08x", ul, dl);

            if (slice_id) {
                bpf_map_update_elem(bpf_map__fd(skel->maps.teid_slice_map), &ul, &slice_id, BPF_ANY);
                bpf_map_update_elem(bpf_map__fd(skel->maps.teid_slice_map), &dl, &slice_id, BPF_ANY);
                printf(" [Slice %u]", slice_id);
            }
            printf("\n");
        } else {
            __u32 teid = strtoul(arg, NULL, 0);
            __u8 one = 1;
            bpf_map_update_elem(bpf_map__fd(skel->maps.tracked_teids), &teid, &one, BPF_ANY);
            printf("Tracking single TEID 0x%08x", teid);

            if (slice_id) {
                bpf_map_update_elem(bpf_map__fd(skel->maps.teid_slice_map), &teid, &slice_id, BPF_ANY);
                printf(" [Slice %u]", slice_id);
            }
            printf("\n");
        }
    }

    /* attach tc ingress */
    opts_ingress = (struct bpf_tc_opts){
        .sz = sizeof(struct bpf_tc_opts),
        .handle = hndl,
        .priority = prio,
        .prog_fd = bpf_program__fd(skel->progs.tc_gtp_teid_ingress),
    };
    hook.attach_point = BPF_TC_INGRESS;
    if (bpf_tc_attach(&hook, &opts_ingress)) {
        fprintf(stderr, "Failed to attach ingress program\n");
        cleanup();
        return 1;
    }

    /* attach tc egress */
    opts_egress = (struct bpf_tc_opts){
        .sz = sizeof(struct bpf_tc_opts),
        .handle = hndl + 1,
        .priority = prio,
        .prog_fd = bpf_program__fd(skel->progs.tc_gtp_teid_egress),
    };
    hook.attach_point = BPF_TC_EGRESS;
    if (bpf_tc_attach(&hook, &opts_egress)) {
        fprintf(stderr, "Failed to attach egress program\n");
        cleanup();
        return 1;
    }

    struct perf_buffer *pb_latency =
        perf_buffer__new(bpf_map__fd(skel->maps.latency_events),
                         8 /*pages*/, handle_latency_event, NULL, NULL, NULL);
    if (!pb_latency) {
        fprintf(stderr, "Failed to open latency perf buffer\n");
        cleanup();
        return 1;
    }

    printf("Monitoring GTP TEID + latency on %s (prio=%d handle=%d)...\n", iface, prio, hndl);
    while (!exiting) {
        perf_buffer__poll(pb_latency, 100 /* ms */);
    }

    perf_buffer__free(pb_latency);
    cleanup();
    return 0;
}