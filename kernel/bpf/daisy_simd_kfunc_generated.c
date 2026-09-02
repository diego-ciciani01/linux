// SPDX-License-Identifier: GPL-2.0
/*
 * Generated DAISY SIMD kfunc microbenchmarks.
 *
 * The AVX-512 asm is deliberately unrolled to avoid runtime loop overhead.
 * Verify the final vmlinux disassembly before benchmarking.
 *
 * This follows the same experimental inline-asm approach as the current
 * bpf_daisy_simd implementation. It declares "memory" but not explicit ZMM
 * compiler clobbers; this is acceptable only as an experimental kernel
 * microbenchmark under the same assumptions as the existing implementation.
 */

#include <linux/bpf.h>
#include <linux/btf.h>
#include <linux/btf_ids.h>
#include <linux/init.h>
#include <linux/module.h>

__bpf_kfunc_start_defs();


__bpf_kfunc void bpf_daisy_noop(void *mem, u32 mem__sz)
{
    if (unlikely(mem__sz < 192))
        return;

    /*
     * Keep the pointer observable to the compiler while doing no data work.
     * This retains the BPF->kfunc boundary, normal function entry/exit,
     * and the size check, but no SIMD/data operation.
     */
    asm volatile("" : : "r"(mem) : "memory");
}

__bpf_kfunc void bpf_daisy_simd_2(void *mem, u32 mem__sz)
{
    char *p = mem;

    if (unlikely(mem__sz < 192))
        return;

    asm volatile(
        "vmovdqu32   0(%0), %%zmm0\n\t"
        "vmovdqu32  64(%0), %%zmm1\n\t"
        "vpaddd     %%zmm1, %%zmm0, %%zmm0\n\t"
        "vpxord     %%zmm1, %%zmm0, %%zmm0\n\t"
        "vmovdqu32  %%zmm0, 128(%0)\n\t"
        :
        : "r"(p)
        : "memory"
    );
}

__bpf_kfunc void bpf_daisy_simd_8(void *mem, u32 mem__sz)
{
    char *p = mem;

    if (unlikely(mem__sz < 192))
        return;

    asm volatile(
        "vmovdqu32   0(%0), %%zmm0\n\t"
        "vmovdqu32  64(%0), %%zmm1\n\t"
        "vpaddd     %%zmm1, %%zmm0, %%zmm0\n\t"
        "vpxord     %%zmm1, %%zmm0, %%zmm0\n\t"
        "vpaddd     %%zmm1, %%zmm0, %%zmm0\n\t"
        "vpxord     %%zmm1, %%zmm0, %%zmm0\n\t"
        "vpaddd     %%zmm1, %%zmm0, %%zmm0\n\t"
        "vpxord     %%zmm1, %%zmm0, %%zmm0\n\t"
        "vpaddd     %%zmm1, %%zmm0, %%zmm0\n\t"
        "vpxord     %%zmm1, %%zmm0, %%zmm0\n\t"
        "vmovdqu32  %%zmm0, 128(%0)\n\t"
        :
        : "r"(p)
        : "memory"
    );
}

__bpf_kfunc void bpf_daisy_simd_16(void *mem, u32 mem__sz)
{
    char *p = mem;

    if (unlikely(mem__sz < 192))
        return;

    asm volatile(
        "vmovdqu32   0(%0), %%zmm0\n\t"
        "vmovdqu32  64(%0), %%zmm1\n\t"
        "vpaddd     %%zmm1, %%zmm0, %%zmm0\n\t"
        "vpxord     %%zmm1, %%zmm0, %%zmm0\n\t"
        "vpaddd     %%zmm1, %%zmm0, %%zmm0\n\t"
        "vpxord     %%zmm1, %%zmm0, %%zmm0\n\t"
        "vpaddd     %%zmm1, %%zmm0, %%zmm0\n\t"
        "vpxord     %%zmm1, %%zmm0, %%zmm0\n\t"
        "vpaddd     %%zmm1, %%zmm0, %%zmm0\n\t"
        "vpxord     %%zmm1, %%zmm0, %%zmm0\n\t"
        "vpaddd     %%zmm1, %%zmm0, %%zmm0\n\t"
        "vpxord     %%zmm1, %%zmm0, %%zmm0\n\t"
        "vpaddd     %%zmm1, %%zmm0, %%zmm0\n\t"
        "vpxord     %%zmm1, %%zmm0, %%zmm0\n\t"
        "vpaddd     %%zmm1, %%zmm0, %%zmm0\n\t"
        "vpxord     %%zmm1, %%zmm0, %%zmm0\n\t"
        "vpaddd     %%zmm1, %%zmm0, %%zmm0\n\t"
        "vpxord     %%zmm1, %%zmm0, %%zmm0\n\t"
        "vmovdqu32  %%zmm0, 128(%0)\n\t"
        :
        : "r"(p)
        : "memory"
    );
}

__bpf_kfunc void bpf_daisy_simd_32(void *mem, u32 mem__sz)
{
    char *p = mem;

    if (unlikely(mem__sz < 192))
        return;

    asm volatile(
        "vmovdqu32   0(%0), %%zmm0\n\t"
        "vmovdqu32  64(%0), %%zmm1\n\t"
        "vpaddd     %%zmm1, %%zmm0, %%zmm0\n\t"
        "vpxord     %%zmm1, %%zmm0, %%zmm0\n\t"
        "vpaddd     %%zmm1, %%zmm0, %%zmm0\n\t"
        "vpxord     %%zmm1, %%zmm0, %%zmm0\n\t"
        "vpaddd     %%zmm1, %%zmm0, %%zmm0\n\t"
        "vpxord     %%zmm1, %%zmm0, %%zmm0\n\t"
        "vpaddd     %%zmm1, %%zmm0, %%zmm0\n\t"
        "vpxord     %%zmm1, %%zmm0, %%zmm0\n\t"
        "vpaddd     %%zmm1, %%zmm0, %%zmm0\n\t"
        "vpxord     %%zmm1, %%zmm0, %%zmm0\n\t"
        "vpaddd     %%zmm1, %%zmm0, %%zmm0\n\t"
        "vpxord     %%zmm1, %%zmm0, %%zmm0\n\t"
        "vpaddd     %%zmm1, %%zmm0, %%zmm0\n\t"
        "vpxord     %%zmm1, %%zmm0, %%zmm0\n\t"
        "vpaddd     %%zmm1, %%zmm0, %%zmm0\n\t"
        "vpxord     %%zmm1, %%zmm0, %%zmm0\n\t"
        "vpaddd     %%zmm1, %%zmm0, %%zmm0\n\t"
        "vpxord     %%zmm1, %%zmm0, %%zmm0\n\t"
        "vpaddd     %%zmm1, %%zmm0, %%zmm0\n\t"
        "vpxord     %%zmm1, %%zmm0, %%zmm0\n\t"
        "vpaddd     %%zmm1, %%zmm0, %%zmm0\n\t"
        "vpxord     %%zmm1, %%zmm0, %%zmm0\n\t"
        "vpaddd     %%zmm1, %%zmm0, %%zmm0\n\t"
        "vpxord     %%zmm1, %%zmm0, %%zmm0\n\t"
        "vpaddd     %%zmm1, %%zmm0, %%zmm0\n\t"
        "vpxord     %%zmm1, %%zmm0, %%zmm0\n\t"
        "vpaddd     %%zmm1, %%zmm0, %%zmm0\n\t"
        "vpxord     %%zmm1, %%zmm0, %%zmm0\n\t"
        "vpaddd     %%zmm1, %%zmm0, %%zmm0\n\t"
        "vpxord     %%zmm1, %%zmm0, %%zmm0\n\t"
        "vpaddd     %%zmm1, %%zmm0, %%zmm0\n\t"
        "vpxord     %%zmm1, %%zmm0, %%zmm0\n\t"
        "vmovdqu32  %%zmm0, 128(%0)\n\t"
        :
        : "r"(p)
        : "memory"
    );
}

__bpf_kfunc void bpf_daisy_simd_64(void *mem, u32 mem__sz)
{
    char *p = mem;

    if (unlikely(mem__sz < 192))
        return;

    asm volatile(
        "vmovdqu32   0(%0), %%zmm0\n\t"
        "vmovdqu32  64(%0), %%zmm1\n\t"
        "vpaddd     %%zmm1, %%zmm0, %%zmm0\n\t"
        "vpxord     %%zmm1, %%zmm0, %%zmm0\n\t"
        "vpaddd     %%zmm1, %%zmm0, %%zmm0\n\t"
        "vpxord     %%zmm1, %%zmm0, %%zmm0\n\t"
        "vpaddd     %%zmm1, %%zmm0, %%zmm0\n\t"
        "vpxord     %%zmm1, %%zmm0, %%zmm0\n\t"
        "vpaddd     %%zmm1, %%zmm0, %%zmm0\n\t"
        "vpxord     %%zmm1, %%zmm0, %%zmm0\n\t"
        "vpaddd     %%zmm1, %%zmm0, %%zmm0\n\t"
        "vpxord     %%zmm1, %%zmm0, %%zmm0\n\t"
        "vpaddd     %%zmm1, %%zmm0, %%zmm0\n\t"
        "vpxord     %%zmm1, %%zmm0, %%zmm0\n\t"
        "vpaddd     %%zmm1, %%zmm0, %%zmm0\n\t"
        "vpxord     %%zmm1, %%zmm0, %%zmm0\n\t"
        "vpaddd     %%zmm1, %%zmm0, %%zmm0\n\t"
        "vpxord     %%zmm1, %%zmm0, %%zmm0\n\t"
        "vpaddd     %%zmm1, %%zmm0, %%zmm0\n\t"
        "vpxord     %%zmm1, %%zmm0, %%zmm0\n\t"
        "vpaddd     %%zmm1, %%zmm0, %%zmm0\n\t"
        "vpxord     %%zmm1, %%zmm0, %%zmm0\n\t"
        "vpaddd     %%zmm1, %%zmm0, %%zmm0\n\t"
        "vpxord     %%zmm1, %%zmm0, %%zmm0\n\t"
        "vpaddd     %%zmm1, %%zmm0, %%zmm0\n\t"
        "vpxord     %%zmm1, %%zmm0, %%zmm0\n\t"
        "vpaddd     %%zmm1, %%zmm0, %%zmm0\n\t"
        "vpxord     %%zmm1, %%zmm0, %%zmm0\n\t"
        "vpaddd     %%zmm1, %%zmm0, %%zmm0\n\t"
        "vpxord     %%zmm1, %%zmm0, %%zmm0\n\t"
        "vpaddd     %%zmm1, %%zmm0, %%zmm0\n\t"
        "vpxord     %%zmm1, %%zmm0, %%zmm0\n\t"
        "vpaddd     %%zmm1, %%zmm0, %%zmm0\n\t"
        "vpxord     %%zmm1, %%zmm0, %%zmm0\n\t"
        "vpaddd     %%zmm1, %%zmm0, %%zmm0\n\t"
        "vpxord     %%zmm1, %%zmm0, %%zmm0\n\t"
        "vpaddd     %%zmm1, %%zmm0, %%zmm0\n\t"
        "vpxord     %%zmm1, %%zmm0, %%zmm0\n\t"
        "vpaddd     %%zmm1, %%zmm0, %%zmm0\n\t"
        "vpxord     %%zmm1, %%zmm0, %%zmm0\n\t"
        "vpaddd     %%zmm1, %%zmm0, %%zmm0\n\t"
        "vpxord     %%zmm1, %%zmm0, %%zmm0\n\t"
        "vpaddd     %%zmm1, %%zmm0, %%zmm0\n\t"
        "vpxord     %%zmm1, %%zmm0, %%zmm0\n\t"
        "vpaddd     %%zmm1, %%zmm0, %%zmm0\n\t"
        "vpxord     %%zmm1, %%zmm0, %%zmm0\n\t"
        "vpaddd     %%zmm1, %%zmm0, %%zmm0\n\t"
        "vpxord     %%zmm1, %%zmm0, %%zmm0\n\t"
        "vpaddd     %%zmm1, %%zmm0, %%zmm0\n\t"
        "vpxord     %%zmm1, %%zmm0, %%zmm0\n\t"
        "vpaddd     %%zmm1, %%zmm0, %%zmm0\n\t"
        "vpxord     %%zmm1, %%zmm0, %%zmm0\n\t"
        "vpaddd     %%zmm1, %%zmm0, %%zmm0\n\t"
        "vpxord     %%zmm1, %%zmm0, %%zmm0\n\t"
        "vpaddd     %%zmm1, %%zmm0, %%zmm0\n\t"
        "vpxord     %%zmm1, %%zmm0, %%zmm0\n\t"
        "vpaddd     %%zmm1, %%zmm0, %%zmm0\n\t"
        "vpxord     %%zmm1, %%zmm0, %%zmm0\n\t"
        "vpaddd     %%zmm1, %%zmm0, %%zmm0\n\t"
        "vpxord     %%zmm1, %%zmm0, %%zmm0\n\t"
        "vpaddd     %%zmm1, %%zmm0, %%zmm0\n\t"
        "vpxord     %%zmm1, %%zmm0, %%zmm0\n\t"
        "vpaddd     %%zmm1, %%zmm0, %%zmm0\n\t"
        "vpxord     %%zmm1, %%zmm0, %%zmm0\n\t"
        "vpaddd     %%zmm1, %%zmm0, %%zmm0\n\t"
        "vpxord     %%zmm1, %%zmm0, %%zmm0\n\t"
        "vmovdqu32  %%zmm0, 128(%0)\n\t"
        :
        : "r"(p)
        : "memory"
    );
}


__bpf_kfunc_end_defs();

BTF_KFUNCS_START(daisy_simd_generated_kfunc_ids)
BTF_ID_FLAGS(func, bpf_daisy_noop)
BTF_ID_FLAGS(func, bpf_daisy_simd_2)
BTF_ID_FLAGS(func, bpf_daisy_simd_8)
BTF_ID_FLAGS(func, bpf_daisy_simd_16)
BTF_ID_FLAGS(func, bpf_daisy_simd_32)
BTF_ID_FLAGS(func, bpf_daisy_simd_64)
BTF_KFUNCS_END(daisy_simd_generated_kfunc_ids)

static const struct btf_kfunc_id_set daisy_simd_generated_kfunc_set = {
    .owner = THIS_MODULE,
    .set = &daisy_simd_generated_kfunc_ids,
};

static int __init daisy_simd_generated_kfunc_init(void)
{
    return register_btf_kfunc_id_set(BPF_PROG_TYPE_XDP,
                                     &daisy_simd_generated_kfunc_set);
}
late_initcall(daisy_simd_generated_kfunc_init);
