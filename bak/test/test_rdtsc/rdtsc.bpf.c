#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

struct {
    __uint(type,        BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key,         __u32);
    __type(value,       __u64);
} tsc_map SEC(".maps");

SEC("xdp")
int rdtsc_prog(struct xdp_md *ctx)
{
    __u32 key = 0;
    __u64 tsc = __builtin_readcyclecounter();   /* → opcode 0xf7 */
    bpf_map_update_elem(&tsc_map, &key, &tsc, BPF_ANY);
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
