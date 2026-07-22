#include <stdio.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <net/if.h>
#include <linux/if_link.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#define N_PACKETS 1000

static double get_cpu_mhz() {
    FILE *f = fopen("/proc/cpuinfo", "r");
    char line[256]; double mhz = 0;
    if (f) {
        while (fgets(line, sizeof(line), f))
            if (sscanf(line, "cpu MHz : %lf", &mhz) == 1) break;
        fclose(f);
    }
    return mhz;
}

int main() {
    /* 1. Caricamento e aggancio BPF (senza stampe superflue) */
    struct bpf_object *obj = bpf_object__open("/bin/test_rdtsc/rdtsc.bpf.o");
    if (!obj || bpf_object__load(obj)) return 1;

    int prog_fd = bpf_program__fd(bpf_object__find_program_by_name(obj, "rdtsc_prog"));
    int map_fd = bpf_map__fd(bpf_object__find_map_by_name(obj, "compare_map"));
    int ifindex = if_nametoindex("lo");

    if (bpf_xdp_attach(ifindex, prog_fd, XDP_FLAGS_SKB_MODE, NULL) < 0) return 1;

    /* 2. Statistiche BPF - Pre Trigger */
    struct bpf_prog_info info_before = {}, info_after = {};
    __u32 info_len = sizeof(struct bpf_prog_info);
    bpf_prog_get_info_by_fd(prog_fd, &info_before, &info_len);

    /* 3. Trigger dei pacchetti (UDP verso localhost) */
    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_port = htons(9999),
        .sin_addr.s_addr = htonl(INADDR_LOOPBACK)
    };
    int tx = socket(AF_INET, SOCK_DGRAM, 0);
    for (int i = 0; i < N_PACKETS; i++) {
        sendto(tx, "trigger", 7, 0, (struct sockaddr *)&addr, sizeof(addr));
    }
    close(tx);
    usleep(200000); /* Breve attesa per permettere l'aggiornamento delle statistiche BPF */

    /* 4. Statistiche BPF - Post Trigger */
    bpf_prog_get_info_by_fd(prog_fd, &info_after, &info_len);
    __u64 delta_cnt = info_after.run_cnt - info_before.run_cnt;
    __u64 delta_time = info_after.run_time_ns - info_before.run_time_ns;

    /* 5. Lettura della mappa (eseguita con un ciclo) */
    __u64 vals[4] = {0};
    for (__u32 k = 0; k < 4; k++) {
        bpf_map_lookup_elem(map_fd, &k, &vals[k]);
    }

    /* 6. Calcolo delle performance */
    double hz = get_cpu_mhz() * 1e6;
    double bpftime_ns = (hz > 0) ? (vals[1] - vals[0]) / hz * 1e9 : 0;
    double ktime_ns   = (hz > 0) ? (vals[3] - vals[2]) / hz * 1e9 : 0;
    double avg_run_ns = (delta_cnt > 0) ? (double)delta_time / delta_cnt : 0;

    /* 7. Output minimale ma completo */
    printf("\n--- RISULTATI PERFORMANCE BPF ---\n");
    printf("Esecuzioni (run_cnt) : %llu\n", delta_cnt);
    printf("Tempo medio BPF      : %.3f ns/run\n", avg_run_ns);
    printf("Costo BPF_TIME       : %.3f ns\n", bpftime_ns);
    printf("Costo ktime_get_ns   : %.3f ns\n", ktime_ns);
    if (bpftime_ns > 0)
        printf("Differenza           : %.1fx più lento (ktime vs BPF_TIME)\n\n", ktime_ns / bpftime_ns);

    /* 8. Cleanup */
    bpf_xdp_detach(ifindex, XDP_FLAGS_SKB_MODE, NULL);
    bpf_object__close(obj);
    return 0;
}
