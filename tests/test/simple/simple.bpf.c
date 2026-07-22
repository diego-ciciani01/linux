#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

/* Nessuna mappa → nessun BTF richiesto.
 * Ogni programma ritorna la propria misura come retval (32 bit). */

SEC("xdp")
int bench_tsc(struct xdp_md *ctx)
{
    __u64 a = __builtin_readcyclecounter();
    __u64 b = __builtin_readcyclecounter();
    return (int)(b - a);          /* cicli rdtsc */
}

SEC("xdp")
int bench_ktime(struct xdp_md *ctx)
{
    __u64 c = bpf_ktime_get_ns();
    __u64 d = bpf_ktime_get_ns();
    return (int)(d - c);          /* ns ktime */
}

char _license[] SEC("license") = "GPL";
