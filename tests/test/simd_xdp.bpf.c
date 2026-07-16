#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

/* Tipo vettoriale 512 bit = 16 x int32 = 64 byte */
typedef int bpf_zmm __attribute__((vector_size(64)));

/*
 * Pipeline SIMD:
 *   1. ZMM0 = LOAD [data + 0]      (input_a: 16 int)
 *   2. ZMM1 = LOAD [data + 64]     (input_b: 16 int)
 *   3. ZMM0 = ZMM0 + ZMM1          (VPADDD)
 *   4. ZMM0 = ZMM0 ^ ZMM1          (VPXORD)
 *   5. STORE [data + 128] = ZMM0   (output_c: 16 int)
 *
 * Risultato per ogni corsia i:
 *   output_c[i] = (input_a[i] + input_b[i]) ^ input_b[i]
 */

SEC("xdp")
int simd_prog(struct xdp_md *ctx)
{
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    /* Bounds check: servono almeno 192 byte (3 x 64B) */
    if (data + 192 > data_end)
        return XDP_DROP;

    /* Pipeline SIMD */
    bpf_zmm a   = __builtin_bpf_simd_load(data);
    bpf_zmm b   = __builtin_bpf_simd_load(data + 64);
    bpf_zmm sum = __builtin_bpf_simd_add(a, b);
    bpf_zmm res = __builtin_bpf_simd_xor(sum, b);
    __builtin_bpf_simd_store(data + 128, res);

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
