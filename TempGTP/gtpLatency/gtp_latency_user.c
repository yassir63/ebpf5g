#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <string.h>
#include <net/if.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "gtp_latency.skel.h"
#include "gtp_latency.h"
#include <json-c/json.h>
#include <sys/un.h>
static volatile sig_atomic_t exiting = 0;
static int map_fd_teid_slice = -1;
// Declare global for cleanup
static struct gtp_latency_bpf *skel = NULL;
static struct bpf_tc_hook hook = { .sz = sizeof(struct bpf_tc_hook) };
static struct bpf_tc_opts opts_ingress = {};
static struct bpf_tc_opts opts_egress = {};
static const char *iface = NULL;
static int priority = 1;

static void cleanup() {
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
        gtp_latency_bpf__destroy(skel);
        skel = NULL;
    }

    fprintf(stderr, "✅ Cleanup complete.\n");
}

static void sig_handler(int signo) {
    exiting = 1;
    cleanup();
}

static void handle_teid_event(void *ctx, int cpu, void *data, __u32 size) {
    const struct teid_event_t *evt = data;
    const char *src = evt->source == 0 ? "INGRESS" : "EGRESS ";
    printf("[%s] TEID: 0x%08x\n", src, evt->teid);
}

static void handle_latency_event(void *ctx, int cpu, void *data, __u32 size) {
    const struct latency_event_t *evt = data;
    __u32 slice_id = 0;

    // Lookup slice
    bpf_map_lookup_elem(map_fd_teid_slice, &evt->teid, &slice_id);
//    if (slice_id > 0) {
//        printf("[LATENCY] Slice %u | TEID 0x%08x: %llu ns (sent @ %llu ns, acked @ %llu ns)\n",
//               slice_id, evt->teid, evt->latency_ns, evt->sent_ns, evt->acked_ns);
//    } else {
//        printf("[LATENCY] TEID 0x%08x: %llu ns (sent @ %llu ns, acked @ %llu ns)\n",
//               evt->teid, evt->latency_ns, evt->sent_ns, evt->acked_ns);
//    }

// Convert to JSON
    json_object *root = json_object_new_object();

    char teid_str[12];
    snprintf(teid_str, sizeof(teid_str), "0x%08x", evt->teid);
    json_object_object_add(root, "teid", json_object_new_string(teid_str));
    json_object_object_add(root, "latency_ns", json_object_new_int64(evt->latency_ns));

    json_object_object_add(root, "slice", json_object_new_int(slice_id));

    // Send over UNIX socket
    int sock = socket(AF_UNIX, SOCK_DGRAM, 0);
    if (sock >= 0) {
        struct sockaddr_un addr = { .sun_family = AF_UNIX };
        strcpy(addr.sun_path, "/tmp/gtp_latency.sock");
        sendto(sock, json_object_to_json_string(root), strlen(json_object_to_json_string(root)), 0,
               (struct sockaddr *)&addr, sizeof(addr));
        close(sock);
    }

    json_object_put(root);

}

static void handle_flow_event(void *ctx, int cpu, void *data, __u32 size) {
    const struct flow_event_t *evt = data;
    const char *dir = evt->direction == 0 ? "INGRESS" : "EGRESS";

    if (evt->proto == 255) {
        printf("[FLOW-FAIL] %s TEID 0x%08x: failed to parse flow headers\n",
               dir, evt->teid);
        return;
    }

    char src_ip[16], dst_ip[16];
    snprintf(src_ip, sizeof(src_ip), "%u.%u.%u.%u",
        evt->src_ip & 0xff, (evt->src_ip >> 8) & 0xff,
        (evt->src_ip >> 16) & 0xff, (evt->src_ip >> 24) & 0xff);

    snprintf(dst_ip, sizeof(dst_ip), "%u.%u.%u.%u",
        evt->dst_ip & 0xff, (evt->dst_ip >> 8) & 0xff,
        (evt->dst_ip >> 16) & 0xff, (evt->dst_ip >> 24) & 0xff);

    printf("[FLOW] %s TEID 0x%08x @ %llu ns: %s:%u → %s:%u (proto %u)\n",
           dir, evt->teid, evt->timestamp_ns,
           src_ip, evt->src_port, dst_ip, evt->dst_port, evt->proto);
}

// static const char *step_name(__u8 step) {
//     switch (step) {
//         case 1:   return "GTP_FLAGS";
//         case 2:   return "GTP_OFFSET";
//         case 10:  return "EXT_START_0";
//         case 11:  return "EXT_START_1";
//         case 12:  return "EXT_START_2";
//         case 13:  return "EXT_START_3";
//         case 20:  return "EXT_TYPE_0";
//         case 21:  return "EXT_TYPE_1";
//         case 22:  return "EXT_TYPE_2";
//         case 23:  return "EXT_TYPE_3";
//         case 30:  return "EXT_LEN_0";
//         case 31:  return "EXT_LEN_1";
//         case 32:  return "EXT_LEN_2";
//         case 33:  return "EXT_LEN_3";
//         case 40:  return "EXT_NEXT_TYPE_0";
//         case 41:  return "EXT_NEXT_TYPE_1";
//         case 42:  return "EXT_NEXT_TYPE_2";
//         case 43:  return "EXT_NEXT_TYPE_3";
//         case 99:  return "RETRANSMISSION";
//         case 200: return "PAYLOAD_BYTE";
//         case 201: return "PAYLOAD_OFFSET";
//         case 102: return "IP_VERSION";
//         case 250: return "EXT_FINAL_OFFSET";
//         case 251: return "FAIL_LOAD_EXT_TYPE";
//         case 252: return "FAIL_LOAD_EXT_LEN";
//         case 253: return "FAIL_LOAD_NEXT_TYPE";
//         case 254: return "FAIL_BOUNDS_CHECK";
//         case 255: return "TEID_PARSE_FAIL";
//         default:  return "UNKNOWN_STEP";
//     }
// }

// static void handle_debug_event(void *ctx, int cpu, void *data, __u32 size) {
//     const struct debug_event_t *evt = data;
//     const char *step_str = step_name(evt->step);

//     printf("[DEBUG] TEID 0x%08x | step %-20s → value 0x%x (%u)\n",
//            evt->teid, step_str, evt->value, evt->value);
// }

// static void handle_raw_packet(void *ctx, int cpu, void *data, __u32 size) {
//     const struct raw_packet_t *pkt = data;
//     printf("[PACKET] TEID 0x%08x | len: %u\n", pkt->teid, pkt->len);

//     for (int i = 0; i < pkt->len; i++) {
//         printf("%02x ", pkt->data[i]);
//         if ((i + 1) % 16 == 0)
//             printf("\n");
//     }
//     if (pkt->len % 16 != 0)
//         printf("\n");
// }


int main(int argc, char **argv) {
    iface = argc > 1 ? argv[1] : "n3";
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

    struct gtp_latency_bpf *skel;
    struct bpf_tc_hook hook = {
        .sz = sizeof(struct bpf_tc_hook),
        .ifindex = if_nametoindex(iface),
    };

    if (hook.ifindex == 0) {
        fprintf(stderr, "Could not find interface: %s\n", iface);
        return 1;
    }

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    skel = gtp_latency_bpf__open_and_load();
    map_fd_teid_slice = bpf_map__fd(skel->maps.teid_slice_map);
    if (!skel) {
        fprintf(stderr, "Failed to load BPF skeleton\n");
        return 1;
    }

    for (int i = argi; i < argc; i++) {
        char *arg = argv[i];
        char *at = strchr(arg, '@');
        char *colon = strchr(arg, ':');

        __u32 slice_id = 0;

        if (at) {
            *at = '\0';  // Null-terminate TEID string
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
    struct bpf_tc_opts opts_ingress = {
        .sz = sizeof(struct bpf_tc_opts),
        .handle = hndl,
        .priority = prio,
        .prog_fd = bpf_program__fd(skel->progs.tc_gtp_teid_ingress),
    };

    hook.attach_point = BPF_TC_INGRESS;
    if (bpf_tc_attach(&hook, &opts_ingress)) {
        fprintf(stderr, "Failed to attach ingress program\n");
        return 1;
    }

    struct bpf_tc_opts opts_egress = {
        .sz = sizeof(struct bpf_tc_opts),
        .handle = hndl + 1,
        .priority = prio,
        .prog_fd = bpf_program__fd(skel->progs.tc_gtp_teid_egress),
    };

    hook.attach_point = BPF_TC_EGRESS;
    if (bpf_tc_attach(&hook, &opts_egress)) {
        fprintf(stderr, "Failed to attach egress program\n");
        return 1;
    }

    struct perf_buffer *pb_latency = perf_buffer__new(
        bpf_map__fd(skel->maps.latency_events), 8, handle_latency_event, NULL, NULL, NULL);
    // struct perf_buffer *pb_debug = perf_buffer__new(
    //     bpf_map__fd(skel->maps.debug_events), 8, handle_debug_event, NULL, NULL, NULL);
    // struct perf_buffer *pb_raw = perf_buffer__new(
    //     bpf_map__fd(skel->maps.raw_packet_events), 8, handle_raw_packet, NULL, NULL, NULL);

    // if (!pb_latency || !pb_debug || !pb_raw) {
    //     fprintf(stderr, "Failed to open perf buffers\n");
    //     return 1;
    // }

    printf("Monitoring GTP TEID + latency + flow + raw packets on %s...\n", iface);
    while (!exiting) {
        perf_buffer__poll(pb_latency, 100);
        // perf_buffer__poll(pb_debug, 100);
        // perf_buffer__poll(pb_raw, 100);
    }

    cleanup();
    return 0;
}
