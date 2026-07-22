#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <sys/syscall.h>
#include <linux/bpf.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define BPF_RAW_INSN(CODE, DST, SRC, OFF, IMM) \
    ((struct bpf_insn){ .code=(CODE), .dst_reg=(DST), \
                        .src_reg=(SRC), .off=(OFF), .imm=(IMM) })

static int bpf_call(enum bpf_cmd cmd, union bpf_attr *attr) {
    return syscall(__NR_bpf, cmd, attr, sizeof(*attr));
}

int main(void) {
    int ret = 0;

    /* 1. Crea mappa */
    union bpf_attr map_attr = {
        .map_type    = BPF_MAP_TYPE_ARRAY,
        .key_size    = sizeof(uint32_t),
        .value_size  = sizeof(uint64_t),
        .max_entries = 1,
    };
    int map_fd = bpf_call(BPF_MAP_CREATE, &map_attr);
    if (map_fd < 0) { perror("[FAIL] map create"); return 1; }
    printf("[OK] mappa creata fd=%d\n", map_fd);

    /* 2. Programma BPF
     *
     *  r2 = fp - 8          puntatore alla chiave
     *  *(u32*)(fp-8) = 0    chiave = 0
     *  r1 = map_fd
     *  call lookup_elem     r0 = &map[0]
     *  if r0 == 0: exit
     *  r3 = r0              salva puntatore (rdtsc sovrascriverà r0)
     *  0xc0 → r1            IL TUO OPCODE: rdtsc in r1
     *  *(u64*)(r3+0) = r1   salva nella mappa
     *  r0 = 1
     *  exit
     */
    struct bpf_insn prog[] = {
        BPF_RAW_INSN(0xbf, 2, 10,  0,  0),   /* r2 = r10             */
        BPF_RAW_INSN(0x07, 2,  0,  0, -8),   /* r2 += -8             */
        BPF_RAW_INSN(0x62,10,  0, -8,  0),   /* *(u32*)(fp-8) = 0    */
        BPF_RAW_INSN(0x18, 1,  1,  0, map_fd),/* r1 = map_fd lo      */
        BPF_RAW_INSN(0x00, 0,  0,  0,  0),   /*              hi      */
        BPF_RAW_INSN(0x85, 0,  0,  0,  1),   /* call lookup_elem     */
        BPF_RAW_INSN(0x15, 0,  0,  3,  0),   /* if r0==0 skip 3      */
        BPF_RAW_INSN(0xbf, 3,  0,  0,  0),   /* r3 = r0              */
        BPF_RAW_INSN(0xf7, 1,  0,  0,  0),   /* *** rdtsc → r1 ***   */
        BPF_RAW_INSN(0x7b, 3,  1,  0,  0),   /* *(u64*)(r3) = r1     */
        BPF_RAW_INSN(0xb7, 0,  0,  0,  1),   /* r0 = 1               */
        BPF_RAW_INSN(0x95, 0,  0,  0,  0),   /* exit                 */
    };

    /* 3. Carica programma */
    char log_buf[8192] = {};
    union bpf_attr prog_attr = {
        .prog_type = BPF_PROG_TYPE_SOCKET_FILTER,
        .insns     = (uint64_t)(uintptr_t)prog,
        .insn_cnt  = sizeof(prog) / sizeof(prog[0]),
        .license   = (uint64_t)(uintptr_t)"GPL",
        .log_buf   = (uint64_t)(uintptr_t)log_buf,
        .log_size  = sizeof(log_buf),
        .log_level = 1,
    };
    int prog_fd = bpf_call(BPF_PROG_LOAD, &prog_attr);
    if (prog_fd < 0) {
        fprintf(stderr, "[FAIL] prog load: %s\n", strerror(errno));
        fprintf(stderr, "--- verifier log ---\n%s\n", log_buf);
        return 1;
    }
    printf("[OK] programma caricato fd=%d\n", prog_fd);

    /* 4. Attach a un socket UDP loopback — niente ping necessario */
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) { perror("[FAIL] socket"); return 1; }

    struct sockaddr_in addr = {
        .sin_family      = AF_INET,
        .sin_port        = htons(9999),
        .sin_addr.s_addr = htonl(INADDR_LOOPBACK),
    };
    bind(sock, (struct sockaddr*)&addr, sizeof(addr));

    if (setsockopt(sock, SOL_SOCKET, SO_ATTACH_BPF,
                   &prog_fd, sizeof(prog_fd)) < 0) {
        perror("[FAIL] SO_ATTACH_BPF"); return 1;
    }
    printf("[OK] programma attaccato al socket UDP\n");

    /* 5. Triggera inviando un pacchetto UDP a se stesso */
    int tx = socket(AF_INET, SOCK_DGRAM, 0);
    char pkt[] = "trigger";
    for (int i = 0; i < 3; i++) {
        sendto(tx, pkt, sizeof(pkt), 0,
               (struct sockaddr*)&addr, sizeof(addr));
    }
    close(tx);
    usleep(100000); /* 100ms — più che sufficiente */

    /* 6. Leggi dalla mappa */
    uint32_t key = 0;
    uint64_t tsc = 0, tsc2 = 0;
    union bpf_attr lu = {
        .map_fd = map_fd,
        .key    = (uint64_t)(uintptr_t)&key,
        .value  = (uint64_t)(uintptr_t)&tsc,
    };
    if (bpf_call(BPF_MAP_LOOKUP_ELEM, &lu) < 0) {
        perror("[FAIL] map lookup"); return 1;
    }

    /* 7. Risultati */
    printf("\n========== RISULTATI ==========\n");
    if (tsc == 0) {
        printf("[FAIL] TSC = 0 — opcode non ha scritto nulla\n");
        ret = 1;
    } else {
        printf("[OK] rdtsc = %llu cicli\n", (unsigned long long)tsc);

        /* Leggi MHz da /proc/cpuinfo per stima tempo */
        double mhz = 0;
        FILE *f = fopen("/proc/cpuinfo", "r");
        if (f) {
            char line[256];
            while (fgets(line, sizeof(line), f))
                if (sscanf(line, "cpu MHz : %lf", &mhz) == 1) break;
            fclose(f);
        }
        if (mhz > 0)
            printf("     ~ %.6f s dal reset TSC (a %.0f MHz)\n",
                   (double)tsc / (mhz * 1e6), mhz);
    }

    /* Sanity check: il secondo pacchetto deve avere TSC > primo */
    lu.value = (uint64_t)(uintptr_t)&tsc2;
    bpf_call(BPF_MAP_LOOKUP_ELEM, &lu);
    /* la mappa viene sovrascritta ad ogni pacchetto */
    /* tsc2 è l'ultimo dei 3 pacchetti inviati        */
    if (tsc2 > 0 && tsc2 >= tsc)
        printf("[OK] TSC monotono: %llu (ultimo dei 3 pkt)\n",
               (unsigned long long)tsc2);
    else
        printf("[WARN] TSC non monotono — controlla l'implementazione\n");

    printf("================================\n");

    close(sock);
    close(prog_fd);
    close(map_fd);
    return ret;
}
