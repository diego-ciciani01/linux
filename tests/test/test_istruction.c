nclude <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <sys/syscall.h>
#include <linux/bpf.h>

#define BPF_RAW_INSN(CODE, DST, SRC, OFF, IMM) \
    ((struct bpf_insn){ .code=(CODE), .dst_reg=(DST), \
                        .src_reg=(SRC), .off=(OFF), .imm=(IMM) })

static int bpf_syscall(enum bpf_cmd cmd, union bpf_attr *attr) {
    return syscall(__NR_bpf, cmd, attr, sizeof(*attr));
}

int main(void) {

    /* ---------- 1. Mappa array: 1 slot da 8 byte ---------- */
    union bpf_attr map_attr = {
        .map_type    = BPF_MAP_TYPE_ARRAY,
        .key_size    = sizeof(uint32_t),
        .value_size  = sizeof(uint64_t),
        .max_entries = 1,
    };
    int map_fd = bpf_syscall(BPF_MAP_CREATE, &map_attr);
    if (map_fd < 0) { perror("map create"); return 1; }
    printf("[OK] mappa creata fd=%d\n", map_fd);

    /* ---------- 2. Programma BPF ----------
 *      *
 *           *  r0 = 0                          ; valore di ritorno di default
 *                *  r1 = map_fd                     ; primo arg lookup
 *                     *  r2 = fp-8                       ; puntatore alla chiave
 *                          *  *(u32*)(fp-8) = 0               ; chiave = 0
 *                               *  call bpf_map_lookup_elem        ; r0 = &map[0]
 *                                    *  if r0 == 0 goto exit            ; null-check
 *                                         *  r3 = r0                         ; salva puntatore al valore
 *                                              *
 *                                                   *  *** 0xc0: rdtsc → r1 ***
 *                                                        *  BPF_RAW_INSN(0xc0, dst=1, src=0, off=0, imm=0)
 *                                                             *
 *                                                                  *  *(u64*)(r3+0) = r1              ; scrivi rdtsc nella mappa
 *                                                                       *  r0 = 1                          ; passa il pacchetto
 *                                                                            *  exit
 *                                                                                 */
    struct bpf_insn prog[] = {
        /* r2 = fp - 8  (indirizzo chiave sullo stack) */
        BPF_RAW_INSN(0xbf, 2, 10, 0, 0),       /* r2 = r10          */
        BPF_RAW_INSN(0x07, 2,  0, 0, -8),      /* r2 += -8          */
        /* *(u32*)(fp-8) = 0 */
        BPF_RAW_INSN(0x62, 10, 0, -8, 0),      /* key = 0           */
        /* r1 = map_fd */
        BPF_RAW_INSN(0x18, 1, 1, 0, map_fd),   /* LD_MAP_FD lo      */
        BPF_RAW_INSN(0x00, 0, 0, 0, 0),        /* LD_MAP_FD hi      */
        /* call bpf_map_lookup_elem */
        BPF_RAW_INSN(0x85, 0, 0, 0, 1),        /* call #1           */
        /* null-check: if r0 == 0 goto exit (salta 3 istruzioni) */
        BPF_RAW_INSN(0x15, 0, 0, 3, 0),        /* if r0==0 skip     */
        /* r3 = r0  (salva puntatore prima che rdtsc lo sovrascriva) */
        BPF_RAW_INSN(0xbf, 3, 0, 0, 0),        /* r3 = r0           */

        /* *** IL TUO OPCODE: rdtsc → r1 *** */
        BPF_RAW_INSN(0xc0, 1, 0, 0, 0),        /* r1 = rdtsc()      */

        /* *(u64*)(r3) = r1 */
        BPF_RAW_INSN(0x7b, 3, 1, 0, 0),        /* map[0] = r1       */
        /* r0 = 1; exit */
        BPF_RAW_INSN(0xb7, 0, 0, 0, 1),
        BPF_RAW_INSN(0x95, 0, 0, 0, 0),        /* exit              */
    };

    /* ---------- 3. Carica il programma ---------- */
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
    int prog_fd = bpf_syscall(BPF_PROG_LOAD, &prog_attr);
    if (prog_fd < 0) {
        fprintf(stderr, "[FAIL] prog load: %s\n", strerror(errno));
        fprintf(stderr, "--- verifier log ---\n%s\n", log_buf);
        return 1;
    }
    printf("[OK] programma caricato fd=%d\n", prog_fd);

    /* ---------- 4. Socket raw + attach ---------- */
    int sock = socket(AF_PACKET, SOCK_RAW, htons(0x0003)); /* ETH_P_ALL */
    if (sock < 0) { perror("socket"); return 1; }
    if (setsockopt(sock, SOL_SOCKET, SO_ATTACH_BPF,
                   &prog_fd, sizeof(prog_fd)) < 0) {
        perror("SO_ATTACH_BPF"); return 1;
    }
    printf("[OK] programma attaccato al socket\n");

    /* ---------- 5. Triggera con un ping loopback ---------- */
    printf("[..] ping loopback per triggerare il programma...\n");
    system("ping -c 1 -W 1 127.0.0.1 > /dev/null 2>&1");
    sleep(1);

    /* ---------- 6. Leggi il risultato dalla mappa ---------- */
    uint32_t key = 0;
    uint64_t tsc = 0;
    union bpf_attr lookup = {
        .map_fd = map_fd,
        .key    = (uint64_t)(uintptr_t)&key,
        .value  = (uint64_t)(uintptr_t)&tsc,
    };
    if (bpf_syscall(BPF_MAP_LOOKUP_ELEM, &lookup) < 0) {
        perror("map lookup"); return 1;
    }

    /* ---------- 7. Risultato ---------- */
    if (tsc == 0) {
        printf("[FAIL] TSC ancora 0 — l'opcode non ha scritto nulla\n");
        return 1;
    }

    printf("[OK] rdtsc letto dalla mappa : %llu cicli\n",
           (unsigned long long)tsc);

    /* Stima frequenza CPU da /proc/cpuinfo per convertire in ms */
    double mhz = 0;
    FILE *f = fopen("/proc/cpuinfo", "r");
    if (f) {
        char line[256];
        while (fgets(line, sizeof(line), f)) {
            if (sscanf(line, "cpu MHz : %lf", &mhz) == 1) break;
        }
        fclose(f);
    }
    if (mhz > 0) {
        double sec = (double)tsc / (mhz * 1e6);
        printf("     stima tempo dal boot : %.3f s  (a %.0f MHz)\n", sec, mhz);
    }

    /* Sanity check: due letture consecutive devono crescere */
    printf("[..] secondo trigger per sanity check...\n");
    uint64_t tsc2 = 0;
    system("ping -c 1 -W 1 127.0.0.1 > /dev/null 2>&1");
    sleep(1);
    lookup.value = (uint64_t)(uintptr_t)&tsc2;
    bpf_syscall(BPF_MAP_LOOKUP_ELEM, &lookup);

    if (tsc2 > tsc)
        printf("[OK] TSC cresce correttamente: %llu > %llu  (delta=%llu)\n",
               (unsigned long long)tsc2,
               (unsigned long long)tsc,
               (unsigned long long)(tsc2 - tsc));
    else
        printf("[WARN] TSC non cresciuto — possibile problema di wrapping o registrazione\n");

    close(sock);
    close(prog_fd);
    close(map_fd);
    return 0;
}
