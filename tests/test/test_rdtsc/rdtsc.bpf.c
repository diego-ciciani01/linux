#include <linux/bpf.h>
#include <linux/types.h>
#include <bpf/bpf_helpers.h>

struct {
    __uint(type,        BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 4);
    __type(key,         __u32);
    __type(value,       __u64);
} compare_map SEC(".maps");

SEC("xdp")
int rdtsc_prog(struct xdp_md *ctx)
{
    __u32 k0 = 0, k1 = 1, k2 = 2, k3 = 3;

     __u64 t1 = __builtin_readcyclecounter();
     __u64 t2 = __builtin_readcyclecounter();

    __u64 tsc_before = __builtin_readcyclecounter();
    __u64 ktime      = bpf_ktime_get_ns();
    __u64 tsc_after  = __builtin_readcyclecounter();

    bpf_map_update_elem(&compare_map, &k0, &t1, BPF_ANY);
    bpf_map_update_elem(&compare_map, &k1, &t2,      BPF_ANY);
    bpf_map_update_elem(&compare_map, &k2, &tsc_before,  BPF_ANY);
    bpf_map_update_elem(&compare_map, &k3, &tsc_after,  BPF_ANY);

    (void)ktime;

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
