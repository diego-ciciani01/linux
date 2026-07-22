#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

// Definiamo il SEC su XDP
SEC("xdp")
int xdp_time_prog(struct xdp_md *ctx) {
    // Leggiamo il timestamp in nanosecondi
    __u64 ts = bpf_ktime_get_ns();

    // Stampiamo nel log del kernel ad ogni pacchetto ricevuto
    bpf_printk("Pacchetto intercettato da XDP! TS: %llu ns\n", ts);

    // Permetti al pacchetto di continuare il suo percorso nella rete
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
