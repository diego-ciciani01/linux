#include <linux/bpf.h>
#include <linux/btf.h>
#include <linux/btf_ids.h>
#include <linux/module.h>

#include <asm/fpu/api.h>

__bpf_kfunc_start_defs();

/*
 * Same computation as native simd_1:
 *
 * out[i] = (a[i] + b[i]) ^ b[i]
 *
 * 16 x i32 = 64 bytes.
 *
 * IMPORTANT:
 * kernel_fpu_begin/end are NOT called here.
 * The kfunc is expected to execute inside the FPU-protected
 * NAPI RX region.
 */
__bpf_kfunc void bpf_daisy_simd(void *mem, u32 mem__sz)
{
        char *p = mem;

        /*
         * The BPF program will pass a 192-byte packet region:
         *
         * p +   0 -> A
         * p +  64 -> B
         * p + 128 -> output
         */

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

__bpf_kfunc_end_defs();

BTF_KFUNCS_START(daisy_simd_kfunc_set)
BTF_ID_FLAGS(func, bpf_daisy_simd)
BTF_KFUNCS_END(daisy_simd_kfunc_set)

static const struct btf_kfunc_id_set daisy_simd_kfuncs = {
        .owner = THIS_MODULE,
        .set   = &daisy_simd_kfunc_set,
};

static int __init daisy_simd_kfunc_init(void)
{
        return register_btf_kfunc_id_set(BPF_PROG_TYPE_XDP,
                                         &daisy_simd_kfuncs);
}

late_initcall(daisy_simd_kfunc_init);
