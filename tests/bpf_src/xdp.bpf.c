#include "pybpf.bpf.h"

BPF_ARRAY(packet_count, int, 1, 0);

SEC("xdp")
int xdp_prog(struct xdp_md *ctx) {
    int zero = 0;
    int *count = bpf_map_lookup_elem(&packet_count, &zero);
    if (!count)
        return XDP_PASS;
    lock_xadd(count, 1);
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
