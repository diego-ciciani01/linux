/* test_simd.c — test userspace per AVX-512 custom nel JIT eBPF
 *
 * Pipeline testata:
 *   LOAD input_a  → ZMM0        (sub_op=5)
 *   LOAD input_b  → ZMM1        (sub_op=5)
 *   VPADDD ZMM0  += ZMM1        (sub_op=1)
 *   VPXORD ZMM0  ^= ZMM1        (sub_op=4)
 *   STORE ZMM0   → output_c     (sub_op=6)
 *
 * Risultato atteso per ogni corsia i:
 *   step1: ZMM0[i] = input_a[i] + input_b[i]
 *   step2: ZMM0[i] = (input_a[i] + input_b[i]) ^ input_b[i]
 *
 * Con input_a[i]=i*10, input_b[i]=5:
 *   ZMM0[i] = (i*10 + 5) ^ 5
 *
 * Strategia di validazione prima delle SIMD:
 *   Usiamo BPF_ST standard (mov scalare) per scrivere sentinelle
 *   a offset 0 e 128 dal buffer. Se arrivano in data_out, il
 *   puntatore R2 è corretto e il meccanismo XDP copy funziona.
 *
 * Struttura del programma BPF (18 istruzioni, indici 0-17):
 *
 *   idx  0: R2 = data          (LDX BPF_W, off=0)
 *   idx  1: R3 = data_end      (LDX BPF_W, off=4)
 *   idx  2: R4 = R2
 *   idx  3: R4 += 192          (3 blocchi × 64B)
 *   idx  4: if R4 > R3: jmp+12 → idx 17 (fallback OOB)
 *   idx  5: [R2+0]   = 0x11111111  (sentinella input_a[0])
 *   idx  6: [R2+128] = 0x22222222  (sentinella output_c[0])
 *   idx  7: ZMM0 = [R2]            (LOAD input_a,   sub_op=5)
 *   idx  8: R2 += 64
 *   idx  9: ZMM1 = [R2]            (LOAD input_b,   sub_op=5)
 *   idx 10: ZMM0 += ZMM1           (VPADDD,         sub_op=1)
 *   idx 11: ZMM0 ^= ZMM1           (VPXORD,         sub_op=4)
 *   idx 12: R2 += 64
 *   idx 13: [R2] = ZMM0            (STORE output_c, sub_op=6)
 *   idx 14: R0 = 42
 *   idx 15: EXIT                   ← percorso normale
 *   idx 16: R0 = 1
 *   idx 17: EXIT                   ← fallback OOB
 *
 * Offset JGT: dst=idx17, src=idx4 → off = 17 - 4 - 1 = 12 ✓
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <linux/bpf.h>
#include <linux/unistd.h>
#include <stdint.h>

/* Layout del pacchetto: tre blocchi consecutivi da 64 byte ciascuno */
struct simd_packet {
    int input_a[16];    /* offset   0 — sorgente A */
    int input_b[16];    /* offset  64 — sorgente B */
    int output_c[16];   /* offset 128 — risultato */
};

/* Opcode custom SIMD: BPF_ALU64 | 0xe0 = 0xe7 */
#define BPF_SIMD  0xe7
#define PROBE_A   0x11111111
#define PROBE_C   0x22222222

/* Dump esadecimale di un buffer */
static void dump_hex(const char *label, const void *buf, int len)
{
    const unsigned char *p = (const unsigned char *)buf;
    printf("  %-10s:", label);
    for (int i = 0; i < len; i++) {
        if (i % 16 == 0) printf("\n    %04x: ", i);
        printf("%02x ", p[i]);
    }
    printf("\n");
}

int main(void)
{
    /* ----------------------------------------------------------
     * Programma BPF
     * ---------------------------------------------------------- */
    struct bpf_insn prog[] = {
        /* idx  0 — R2 = data (BPF_W: il JIT XDP converte in ptr 64-bit) */
        { .code = BPF_LDX|BPF_MEM|BPF_W,   .dst_reg=2,.src_reg=1,.off=0, .imm=0 },

        /* idx  1 — R3 = data_end */
        { .code = BPF_LDX|BPF_MEM|BPF_W,   .dst_reg=3,.src_reg=1,.off=4, .imm=0 },

        /* idx  2 — R4 = R2  (copia per bounds check senza toccare R2) */
        { .code = BPF_ALU64|BPF_MOV|BPF_X, .dst_reg=4,.src_reg=2,.off=0, .imm=0 },

        /* idx  3 — R4 += 192 */
        { .code = BPF_ALU64|BPF_ADD|BPF_K, .dst_reg=4,.src_reg=0,.off=0, .imm=192 },

        /* idx  4 — if R4 > R3: goto fallback
         * off = 17 - 4 - 1 = 12 */
        { .code = BPF_JMP|BPF_JGT|BPF_X, .dst_reg=4,.src_reg=3,.off=11,.imm=0 },

        /* idx  5 — SENTINELLA A: scrivi 0x11111111 in input_a[0] = [R2+0] */
        { .code = BPF_ST|BPF_MEM|BPF_W,    .dst_reg=2,.src_reg=0,.off=0, .imm=PROBE_A },

        /* idx  6 — SENTINELLA C: scrivi 0x22222222 in output_c[0] = [R2+128] */
        { .code = BPF_ST|BPF_MEM|BPF_W,    .dst_reg=2,.src_reg=0,.off=128,.imm=PROBE_C },

        /* idx  7 — SIMD LOAD: ZMM0 = [R2]   (R2 punta a input_a) */
        { .code = BPF_SIMD, .dst_reg=0,.src_reg=2,.off=0,.imm=5 },

        /* idx  8 — R2 += 64  (ora R2 punta a input_b) */
        { .code = BPF_ALU64|BPF_ADD|BPF_K, .dst_reg=2,.src_reg=0,.off=0, .imm=64 },

        /* idx  9 — SIMD LOAD: ZMM1 = [R2]   (R2 punta a input_b) */
        { .code = BPF_SIMD, .dst_reg=1,.src_reg=2,.off=0,.imm=5 },

        /* idx 10 — SIMD VPADDD: ZMM0 = ZMM0 + ZMM1 */
        { .code = BPF_SIMD, .dst_reg=0,.src_reg=1,.off=0,.imm=1 },

        /* idx 11 — SIMD VPXORD: ZMM0 = ZMM0 ^ ZMM1 */
        { .code = BPF_SIMD, .dst_reg=0,.src_reg=1,.off=0,.imm=4 },

        /* idx 12 — R2 += 64  (ora R2 punta a output_c) */
        { .code = BPF_ALU64|BPF_ADD|BPF_K, .dst_reg=2,.src_reg=0,.off=0, .imm=64 },

        /* idx 13 — SIMD STORE: [R2] = ZMM0  (R2 punta a output_c) */
        { .code = BPF_SIMD, .dst_reg=2,.src_reg=0,.off=0,.imm=6 },

        /* idx 14 — R0 = 42 */
        { .code = BPF_ALU64|BPF_MOV|BPF_K, .dst_reg=0,.src_reg=0,.off=0, .imm=42 },

        /* idx 15 — EXIT (percorso normale) */
        { .code = BPF_JMP|BPF_EXIT },

        /* idx 16 — R0 = 1  (fallback bounds check) */
        { .code = BPF_ALU64|BPF_MOV|BPF_K, .dst_reg=0,.src_reg=0,.off=0, .imm=1 },

        /* idx 17 — EXIT (fallback) */
        { .code = BPF_JMP|BPF_EXIT },
    };

    const int insn_count = (int)(sizeof(prog) / sizeof(prog[0]));

    /* Verifica statica degli offset (fallisce a compile time se sbagliato) */
    if (prog[4].off != 11) {
        fprintf(stderr, "[-] BUG: offset JGT errato %d\n",
                prog[4].off);
        return 1;
    }
    if (insn_count != 18) {
        fprintf(stderr, "[-] BUG: attese 18 istruzioni, trovate %d\n", insn_count);
        return 1;
    }

    printf("[*] Programma: %d istruzioni, offset JGT=%d ✓\n",
           insn_count, prog[4].off);

    /* ----------------------------------------------------------
     * Preparazione dati di input
     * ---------------------------------------------------------- */
    struct simd_packet packet;
    memset(&packet, 0, sizeof(packet));

    for (int i = 0; i < 16; i++) {
        packet.input_a[i] = i * 10;   /* 0, 10, 20, ..., 150 */
        packet.input_b[i] = 5;         /* 5 fisso per tutte le corsie */
    }

    printf("[*] sizeof(simd_packet) = %zu B (atteso 192)\n", sizeof(packet));
    if (sizeof(packet) != 192) {
        fprintf(stderr, "[-] Struttura non è 192 byte!\n");
        return 1;
    }

    printf("[*] Dati PRIMA dell'esecuzione:\n");
    dump_hex("input_a",  packet.input_a,  64);
    dump_hex("input_b",  packet.input_b,  64);
    dump_hex("output_c", packet.output_c, 64);

    /* ----------------------------------------------------------
     * Caricamento del programma BPF nel kernel
     * ---------------------------------------------------------- */
    char log_buf[16384];
    memset(log_buf, 0, sizeof(log_buf));

    union bpf_attr load_attr;
    memset(&load_attr, 0, sizeof(load_attr));
    load_attr.prog_type = BPF_PROG_TYPE_XDP;
    load_attr.insns     = (unsigned long)prog;
    load_attr.insn_cnt  = insn_count;
    load_attr.license   = (unsigned long)"GPL";
    load_attr.log_buf   = (unsigned long)log_buf;
    load_attr.log_size  = sizeof(log_buf);
    load_attr.log_level = 1;

    printf("\n[*] BPF_PROG_LOAD...\n");
    int prog_fd = syscall(__NR_bpf, BPF_PROG_LOAD, &load_attr, sizeof(load_attr));
    if (prog_fd < 0) {
        perror("[-] BPF_PROG_LOAD fallito");
        printf("--- LOG VERIFIER ---\n%s\n", log_buf);
        return 1;
    }
    printf("[+] Verifier OK, JIT compilato (fd=%d)\n", prog_fd);

    /* ----------------------------------------------------------
     * Esecuzione tramite BPF_PROG_TEST_RUN
     * ---------------------------------------------------------- */
    union bpf_attr test_attr;
    memset(&test_attr, 0, sizeof(test_attr));
    test_attr.test.prog_fd       = prog_fd;
    test_attr.test.data_in       = (unsigned long)&packet;
    test_attr.test.data_size_in  = sizeof(packet);
    test_attr.test.data_out      = (unsigned long)&packet;
    test_attr.test.data_size_out = sizeof(packet);

    printf("[*] BPF_PROG_TEST_RUN...\n");
    int ret = syscall(__NR_bpf, BPF_PROG_TEST_RUN, &test_attr, sizeof(test_attr));
    if (ret < 0) {
        perror("[-] BPF_PROG_TEST_RUN fallito");
        close(prog_fd);
        return 1;
    }

    printf("[+] Eseguito. retval=%u  data_size_out=%u (atteso %zu)\n",
           test_attr.test.retval,
           test_attr.test.data_size_out,
           sizeof(packet));

    if (test_attr.test.retval == 1) {
        fprintf(stderr, "[-] Fallback OOB: il bounds check è fallito.\n"
                        "    Controlla che data_size_in sia >= 192.\n");
        close(prog_fd);
        return 1;
    }

    /* ----------------------------------------------------------
     * Dump post-esecuzione
     * ---------------------------------------------------------- */
    printf("\n[*] Dati DOPO l'esecuzione:\n");
    dump_hex("input_a",  packet.input_a,  64);
    dump_hex("input_b",  packet.input_b,  64);
    dump_hex("output_c", packet.output_c, 64);

    /* ----------------------------------------------------------
     * Verifica sentinelle (diagnosi puntatore)
     * ----------------------------------------------------------
     * Se le sentinelle sono assenti, il meccanismo XDP copy è rotto
     * o R2 non puntava al buffer. Le SIMD non avrebbero potuto
     * leggere/scrivere i dati giusti.
     * ---------------------------------------------------------- */
    printf("\n--- DIAGNOSI SENTINELLE ---\n");

    int probe_ok = 1;
    if (packet.input_a[0] != PROBE_A) {
        printf("  input_a[0]  = 0x%08x  (atteso 0x%08x) "
               "[FAIL — R2 non punta al buffer o copy non funziona]\n",
               packet.input_a[0], PROBE_A);
        probe_ok = 0;
    } else {
        printf("  input_a[0]  = 0x%08x  [OK — R2 corretto]\n", packet.input_a[0]);
    }

    /* output_c[0] dopo la STORE SIMD:
     * - Se è 0x22222222: la STORE non ha scritto su output_c[0]
     *   → problema nel JIT (FPU o encoding)
     * - Se è (0*10+5)^5 = 0: la STORE ha scritto ZMM0=0 → FPU non funziona
     * - Se è 5^5 = 0: idem
     * - Se è il valore atteso: tutto funziona */
    printf("  output_c[0] = 0x%08x  ", packet.output_c[0]);
    if (packet.output_c[0] == PROBE_C)
        printf("[ATTENZIONE: sentinella non sovrascritta — STORE non ha eseguito]\n");
    else if (packet.output_c[0] == 0)
        printf("[ATTENZIONE: zero — STORE eseguita ma ZMM0=0 (problema FPU context?)]\n");
    else
        printf("[OK — STORE ha scritto 0x%08x]\n", packet.output_c[0]);

    /* ----------------------------------------------------------
     * Verifica risultati SIMD
     *
     * input_a[0] è stato sovrascritto dalla sentinella (0x11111111),
     * quindi la corsia 0 avrà ZMM0[0] = (0x11111111 + 5) ^ 5 =
     * 0x11111116 ^ 5 = 0x11111113.
     * Le altre corsie: ZMM0[i] = (i*10 + 5) ^ 5.
     * ---------------------------------------------------------- */
    printf("\n--- VERIFICA RISULTATI SIMD ---\n");

    int all_ok = 1;
    for (int i = 0; i < 16; i++) {
        int a_actual = (i == 0) ? (int)PROBE_A : i * 10; /* a[0] era la sentinella */
        int b        = 5;
        int expected = (a_actual + b) ^ b;
        int got      = packet.output_c[i];

        if (i == 0)
            printf("  corsia [%02d]: (sentinella 0x%08x + %d) ^ %d = 0x%08x | "
                   "got 0x%08x %s\n",
                   i, PROBE_A, b, b, (unsigned)expected, (unsigned)got,
                   got == expected ? "[OK]" : "[ERRORE]");
        else
            printf("  corsia [%02d]: (%3d + %d) ^ %d = %3d | got %3d %s\n",
                   i, a_actual, b, b, expected, got,
                   got == expected ? "[OK]" : "[ERRORE]");

        if (got != expected) all_ok = 0;
    }

    printf("\n%s\n\n",
           all_ok ? "[+] TUTTI I RISULTATI CORRETTI — AVX-512 SIMD FUNZIONA"
                  : "[-] ALCUNI RISULTATI ERRATI");

    /* ----------------------------------------------------------
     * Guida alla diagnosi se fallisce
     * ---------------------------------------------------------- */
    if (!all_ok) {
        printf("--- GUIDA DIAGNOSI ---\n");
        if (!probe_ok)
            printf("  • Le sentinelle non arrivano: problema nel meccanismo XDP/copy\n");
        else if (packet.output_c[0] == PROBE_C)
            printf("  • Sentinelle OK, STORE non scrive: probabile problema di\n"
                   "    encoding EVEX (displacement sbagliato) o FPU context.\n"
                   "    Controlla che emit_simd_alu riceva mem_off=insn->off\n"
                   "    e che kernel_fpu_begin/end sia integrato nel JIT.\n");
        else if (packet.output_c[0] == 0)
            printf("  • Sentinelle OK, STORE scrive 0: ZMM0 è zero dopo LOAD.\n"
                   "    Questo è il sintomo classico del mancato kernel_fpu_begin.\n"
                   "    Integra emit_fpu_begin/emit_fpu_end dal patch JIT.\n");
        else
            printf("  • Valori non nulli ma sbagliati: problema nel calcolo\n"
                   "    VPADDD/VPXORD o nel mapping registri.\n");
    }

    close(prog_fd);
    return all_ok ? 0 : 1;
}
