/*compilazione:
 *   gcc -static simd_loader.c -o simd_loader \
 *       -I <kernel>/tools/lib \
 *       -L <kernel>/tools/lib/bpf \
 *       -lbpf -lelf -lz
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/syscall.h>
#include <linux/bpf.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

/* Layout del pacchetto: 3 blocchi da 64 byte ciascuno */
struct simd_packet {
    int input_a[16];    /* offset   0 */
    int input_b[16];    /* offset  64 */
    int output_c[16];   /* offset 128 */
};

/* Wrapper per BPF_PROG_TEST_RUN */
static int run_test(int prog_fd, struct simd_packet *pkt)
{
    union bpf_attr attr;
    memset(&attr, 0, sizeof(attr));

    attr.test.prog_fd       = prog_fd;
    attr.test.data_in       = (unsigned long)pkt;
    attr.test.data_size_in  = sizeof(*pkt);
    attr.test.data_out      = (unsigned long)pkt;
    attr.test.data_size_out = sizeof(*pkt);
    attr.test.repeat        = 1;

    return syscall(__NR_bpf, BPF_PROG_TEST_RUN, &attr, sizeof(attr));
}

int main(int argc, char **argv)
{
    const char *obj_path = "simd_xdp.bpf.o";
    struct bpf_object *obj;
    struct bpf_program *prog;
    int prog_fd, err;

    printf("============================================\n");
    printf("  Test SIMD AVX-512 — eBPF/XDP end-to-end\n");
    printf("============================================\n\n");

    /* 1. Apri il file .bpf.o con libbpf */
    printf("[*] Apertura %s ...\n", obj_path);
    obj = bpf_object__open_file(obj_path, NULL);
    if (!obj) {
        fprintf(stderr, "[-] bpf_object__open_file: %s\n", strerror(errno));
        return 1;
    }

    /* 2. Carica nel kernel (verifier + JIT) */
    printf("[*] Caricamento nel kernel...\n");
    err = bpf_object__load(obj);
    if (err) {
        fprintf(stderr, "[-] bpf_object__load: %s\n", strerror(-err));
        bpf_object__close(obj);
        return 1;
    }
    printf("[+] Verifier OK, JIT compilato.\n");

    /* 3. Trova il programma "simd_prog" */
    prog = bpf_object__find_program_by_name(obj, "simd_prog");
    if (!prog) {
        fprintf(stderr, "[-] Programma 'simd_prog' non trovato nel .o\n");
        bpf_object__close(obj);
        return 1;
    }
    prog_fd = bpf_program__fd(prog);
    printf("[+] Programma trovato, fd=%d\n\n", prog_fd);

    /* 4. Prepara dati di test */
    struct simd_packet pkt;
    memset(&pkt, 0, sizeof(pkt));
    for (int i = 0; i < 16; i++) {
        pkt.input_a[i] = i * 10;   /* 0, 10, 20, ..., 150 */
        pkt.input_b[i] = 5;
    }

    printf("[*] Input:\n");
    printf("    input_a = [");
    for (int i = 0; i < 16; i++) printf("%d%s", pkt.input_a[i], i < 15 ? ", " : "");
    printf("]\n");
    printf("    input_b = [");
    for (int i = 0; i < 16; i++) printf("%d%s", pkt.input_b[i], i < 15 ? ", " : "");
    printf("]\n\n");

    /* 5. Esegui con BPF_PROG_TEST_RUN */
    printf("[*] BPF_PROG_TEST_RUN...\n");
    err = run_test(prog_fd, &pkt);
    if (err < 0) {
        fprintf(stderr, "[-] BPF_PROG_TEST_RUN: %s\n", strerror(errno));
        bpf_object__close(obj);
        return 1;
    }
    printf("[+] Eseguito.\n\n");

    /* 6. Verifica risultati */
    /*   output_c[i] = (input_a[i] + input_b[i]) ^ input_b[i]
     *
     *   Nota: input_a e input_b non cambiano perche' le SIMD
     *   scrivono solo su output_c (offset 128).
     */
    printf("--- VERIFICA RISULTATI SIMD ---\n\n");
    int ok = 1;
    for (int i = 0; i < 16; i++) {
        int a = i * 10;
        int b = 5;
        int expected = (a + b) ^ b;
        int got      = pkt.output_c[i];
        printf("  corsia [%02d]: (%3d + %d) ^ %d = %3d | got %3d %s\n",
               i, a, b, b, expected, got,
               got == expected ? "[OK]" : "[ERRORE]");
        if (got != expected) ok = 0;
    }

    printf("\n============================================\n");
    if (ok)
        printf("  RISULTATO: TUTTI I 16 LANES CORRETTI\n");
    else
        printf("  RISULTATO: ERRORI NEI RISULTATI\n");
    printf("============================================\n");

    bpf_object__close(obj);
    return ok ? 0 : 1;
}
