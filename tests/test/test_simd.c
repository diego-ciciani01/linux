#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <linux/bpf.h>
#include <linux/unistd.h>
#include <stdint.h>

struct simd_packet {
    int input_a[16];  /* offset 0 */
    int input_b[16];  /* offset 64 */
    int output_c[16]; /* offset 128 */
};

#define BPF_SIMD 0xe7

/* helper: stampa i byte di un buffer */
static void dump_hex(const char *label, const void *buf, int len)
{
    const unsigned char *p = buf;
    printf("%s:", label);
    for (int i = 0; i < len; i++) {
        if (i % 16 == 0) printf("\n  %04x: ", i);
        printf("%02x ", p[i]);
    }
    printf("\n");
}

int main(void)
{
    /*
     * Pipeline SIMD da testare:
     * 1. LOAD input_a -> ZMM0  (sub_op 5)
     * 2. LOAD input_b -> ZMM1  (sub_op 5)
     * 3. ADD ZMM0, ZMM1        (sub_op 1)  -> ZMM0 = ZMM0 + ZMM1
     * 4. XOR ZMM0, ZMM1        (sub_op 4)  -> ZMM0 = ZMM0 ^ ZMM1
     * 5. STORE ZMM0 -> output_c (sub_op 6)
     */
    struct bpf_insn prog[] = {
        /* idx  0 */ { .code = BPF_LDX|BPF_MEM|BPF_W,      .dst_reg=2,.src_reg=1,.off=0,  .imm=0        },
        /* idx  1 */ { .code = BPF_LDX|BPF_MEM|BPF_W,      .dst_reg=3,.src_reg=1,.off=4,  .imm=0        },
        /* idx  2 */ { .code = BPF_ALU64|BPF_MOV|BPF_X,    .dst_reg=4,.src_reg=2,.off=0,  .imm=0        },
        /* idx  3 */ { .code = BPF_ALU64|BPF_ADD|BPF_K,    .dst_reg=4,.src_reg=0,.off=0,  .imm=192      },
/* idx  4 */ { .code = BPF_JMP|BPF_JGT|BPF_X,      .dst_reg=4,.src_reg=3,.off=12, .imm=0        },
        /* PROBE: scrivi sentinelle via ST standard */
        /* idx  5 */ { .code = BPF_ST|BPF_MEM|BPF_W,       .dst_reg=2,.src_reg=0,.off=0,  .imm=0x11111111 },
        /* idx  6 */ { .code = BPF_ST|BPF_MEM|BPF_W,       .dst_reg=2,.src_reg=0,.off=128,.imm=0x22222222 },

        /* R5 = R2 (registro mobile per SIMD, non tocca R2) */
        /* idx  7 */ { .code = BPF_ALU64|BPF_MOV|BPF_X,    .dst_reg=5,.src_reg=2,.off=0,  .imm=0        },

        /* --- INIZIO SIMD PIPELINE --- */

        /* 1) LOAD: ZMM0 = [R5] (input_a) */
        /* idx  8 */ { .code=BPF_SIMD, .dst_reg=0,.src_reg=5,.off=0,.imm=5 },

        /* Avanza R5 a input_b */
        /* idx  9 */ { .code=BPF_ALU64|BPF_ADD|BPF_K, .dst_reg=5,.src_reg=0,.off=0,.imm=64 },

        /* 2) LOAD: ZMM1 = [R5] (input_b) */
        /* idx 10 */ { .code=BPF_SIMD, .dst_reg=1,.src_reg=5,.off=0,.imm=5 },

        /* 3) ADD: ZMM0 = ZMM0 + ZMM1 */
        /* idx 11 */ { .code=BPF_SIMD, .dst_reg=0,.src_reg=1,.off=0,.imm=1 },

        /* 4) XOR: ZMM0 = ZMM0 ^ ZMM1 */
        /* idx 12 */ { .code=BPF_SIMD, .dst_reg=0,.src_reg=1,.off=0,.imm=4 },

        /* Avanza R5 a output_c */
        /* idx 13 */ { .code=BPF_ALU64|BPF_ADD|BPF_K, .dst_reg=5,.src_reg=0,.off=0,.imm=64 },

        /* 5) STORE: [R5] = ZMM0 (output_c) */
        /* idx 14 */ { .code=BPF_SIMD, .dst_reg=5,.src_reg=0,.off=0,.imm=6 },

        /* --- FINE SIMD PIPELINE --- */

        /* Successo */
        /* idx 15 */ { .code=BPF_ALU64|BPF_MOV|BPF_K, .dst_reg=0,.src_reg=0,.off=0,.imm=42 },
        /* idx 16 */ { .code=BPF_JMP|BPF_EXIT },

        /* Fallback */
        /* idx 17 */ { .code=BPF_ALU64|BPF_MOV|BPF_K, .dst_reg=0,.src_reg=0,.off=0,.imm=1 },
        /* idx 18 */ { .code=BPF_JMP|BPF_EXIT },
    };

    int insn_count = sizeof(prog) / sizeof(prog[0]);
    printf("[*] Istruzioni: %d\n", insn_count);

    /* Verifica offset JGT a compile-time (18 target - 4 current - 1 = 13) */
    if (prog[4].off != 12) {
        fprintf(stderr, "[-] BUG offset JGT: atteso 12, trovato %d\n", prog[4].off);
        return 1;
    }

    /* Dati di test: prepariamo pattern evidenti per lo XOR */
    struct simd_packet packet;
    memset(&packet, 0, sizeof(packet));
    for (int i = 0; i < 16; i++) {
        packet.input_a[i] = i * 10;
        packet.input_b[i] = 0x55555555; /* Pattern a bit alternati, perfetto per lo XOR */
    }

    printf("[*] Buffer input PRIMA dell'esecuzione:\n");
    dump_hex("  input_a ", packet.input_a, 64);
    dump_hex("  input_b ", packet.input_b, 64);
    dump_hex("  output_c", packet.output_c, 64);

    char log_buf[8192];
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

    printf("\n[*] Caricamento programma...\n");
    int prog_fd = syscall(__NR_bpf, BPF_PROG_LOAD, &load_attr, sizeof(load_attr));
    if (prog_fd < 0) {
        perror("[-] BPF_PROG_LOAD fallito");
        printf("--- VERIFIER ---\n%s\n", log_buf);
        return 1;
    }
    printf("[+] Verifier OK\n");

    union bpf_attr test_attr;
    memset(&test_attr, 0, sizeof(test_attr));
    test_attr.test.prog_fd       = prog_fd;
    test_attr.test.data_in       = (unsigned long)&packet;
    test_attr.test.data_size_in  = sizeof(packet);
    test_attr.test.data_out      = (unsigned long)&packet;
    test_attr.test.data_size_out = sizeof(packet);

    printf("[*] Esecuzione BPF_PROG_TEST_RUN...\n");
    int ret = syscall(__NR_bpf, BPF_PROG_TEST_RUN, &test_attr, sizeof(test_attr));
    if (ret < 0) {
        perror("[-] BPF_PROG_TEST_RUN fallito");
        close(prog_fd);
        return 1;
    }

    if (test_attr.test.retval == 1) {
        fprintf(stderr, "[-] Bounds check fallito, pacchetto droppato\n");
        close(prog_fd);
        return 1;
    }

    printf("\n[*] Buffer DOPO l'esecuzione:\n");
    dump_hex("  input_a ", packet.input_a, 64);
    dump_hex("  input_b ", packet.input_b, 64);
    dump_hex("  output_c", packet.output_c, 64);

    printf("\n--- PROBE SENTINELLE ---\n");
    printf("  input_a[0]  = 0x%08x  %s\n", packet.input_a[0],
           packet.input_a[0] == 0x11111111 ? "[OK]" : "[FAIL]");
    printf("  output_c[0] = 0x%08x  %s\n", packet.output_c[0],
           packet.output_c[0] == 0x22222222 ? "[OK (verrà sovrascritto da SIMD)]" : "[FAIL]");

    /* Verifica rigorosa di tutti i casi JIT */
    printf("\n--- VERIFICA RISULTATI SIMD (LOAD, ADD, XOR, STORE) ---\n");
    int ok = 1;
    for (int i = 0; i < 16; i++) {
        /*
         * Ricostruiamo la matematica per verificare che LOAD(5), ADD(1) e XOR(4)
         * abbiano fatto tutti il loro dovere prima dello STORE(6).
         */
        int raw_a = (i == 0) ? 0x11111111 : (i * 10);
        int raw_b = 0x55555555;

        int expected = (raw_a + raw_b) ^ raw_b;
        int got = packet.output_c[i];

        if (i == 0) {
            printf("  corsia [%02d]: (sentinella) expected 0x%08x, got 0x%08x %s\n",
                   i, expected, got, got == expected ? "[OK]" : "[ERRORE]");
        } else {
            printf("  corsia [%02d]: ((%3d + 0x55555555) ^ 0x55555555) = 0x%08x | got 0x%08x %s\n",
                   i, raw_a, expected, got, got == expected ? "[OK]" : "[ERRORE]");
        }

        if (got != expected) ok = 0;
    }

    printf("\n%s\n", ok ? "[+] TUTTE LE ISTRUZIONI SIMD FUNZIONANO (Load, Add, Xor, Store)!" : "[-] ALCUNI RISULTATI ERRATI");
    close(prog_fd);
    return ok ? 0 : 1;
}
