#include <stdio.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <linux/if_link.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>        /* bpf_map_lookup_elem */

static double read_cpu_mhz(void)
{
    FILE *f = fopen("/proc/cpuinfo", "r");
    if (!f) return 0;
    char line[256];
    double mhz = 0;
    while (fgets(line, sizeof(line), f))
        if (sscanf(line, "cpu MHz : %lf", &mhz) == 1) break;
    fclose(f);
    return mhz;
}

int main(void)
{
    /* 1. carica l'oggetto BPF */
    struct bpf_object *obj = bpf_object__open("/bin/test_rdtsc/rdtsc.bpf.o");
    if (!obj) { perror("[FAIL] open"); return 1; }
    if (bpf_object__load(obj)) { perror("[FAIL] load"); return 1; }
    printf("[OK] programma caricato\n");

    /* 2. recupera programma e mappa con check espliciti */
    struct bpf_program *prog =
        bpf_object__find_program_by_name(obj, "rdtsc_prog");
    if (!prog) {
        fprintf(stderr, "[FAIL] 'rdtsc_prog' non trovato nell'oggetto\n");
        return 1;
    }
    int prog_fd = bpf_program__fd(prog);

    struct bpf_map *map =
        bpf_object__find_map_by_name(obj, "compare_map");
    if (!map) {
        fprintf(stderr, "[FAIL] 'compare_map' non trovata nell'oggetto\n");
        return 1;
    }
    int map_fd = bpf_map__fd(map);

    printf("[OK] prog_fd=%d  map_fd=%d\n", prog_fd, map_fd);

    /* 3. attacca a lo via XDP */
    int ifindex = if_nametoindex("lo");
    if (!ifindex) { perror("[FAIL] if_nametoindex"); return 1; }

    if (bpf_xdp_attach(ifindex, prog_fd, XDP_FLAGS_SKB_MODE, NULL) < 0) {
        perror("[FAIL] bpf_xdp_attach"); return 1;
    }
    printf("[OK] programma attaccato a lo (XDP)\n");

    /* 4. triggera con un pacchetto UDP su loopback */
    int tx = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in addr = {
        .sin_family      = AF_INET,
        .sin_port        = htons(9999),
        .sin_addr.s_addr = htonl(INADDR_LOOPBACK),
    };
    char pkt[] = "trigger";
    sendto(tx, pkt, sizeof(pkt), 0, (struct sockaddr *)&addr, sizeof(addr));
    close(tx);
    usleep(100000);

    /* 5. leggi i tre slot dalla mappa */
    __u32 k0 = 0, k1 = 1, k2 = 2;
    __u64 tsc_before = 0, ktime = 0, tsc_after = 0;
    bpf_map_lookup_elem(map_fd, &k0, &tsc_before);
    bpf_map_lookup_elem(map_fd, &k1, &ktime);
    bpf_map_lookup_elem(map_fd, &k2, &tsc_after);

    /* 6. converti e stampa */
    double mhz     = read_cpu_mhz();
    double hz      = mhz * 1e6;
    double tsc_ns  = (hz > 0) ? (double)tsc_before / hz * 1e9 : 0;
    __u64  overhead = tsc_after - tsc_before;

    printf("\n========== CONFRONTO TSC vs ktime_get_ns ==========\n");
    printf("CPU:                    %.0f MHz\n", mhz);
    printf("\n");
    printf("BPF_TIME  (cicli raw):  %llu\n",    tsc_before);
    printf("BPF_TIME  (→ ns):       %.3f\n",    tsc_ns);
    printf("\n");
    printf("ktime_get_ns (ns):      %llu\n",    ktime);
    printf("\n");
    printf("Differenza:             %.3f ns\n",
           tsc_ns - (double)ktime);
    printf("\n");
    printf("Overhead ktime_get_ns:  %llu cicli  (%.3f ns)\n",
           overhead,
           (hz > 0) ? (double)overhead / hz * 1e9 : 0);
    printf("====================================================\n");

    /* 7. stacca e chiudi */
    bpf_xdp_detach(ifindex, XDP_FLAGS_SKB_MODE, NULL);
    bpf_object__close(obj);
    return 0;
}
