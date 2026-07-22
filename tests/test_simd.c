#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <linux/bpf.h>
#include <linux/unistd.h>

// Struttura per mappare i 3 blocchi da 512 bit nel pacchetto
struct simd_packet {
    int input_a[16];  // ZMM0
    int input_b[16];  // ZMM1
    int output_c[16]; // Risultato finale
};

int main() {
    /* * PROGRAMMA eBPF CUSTOM SIMD:
     * 1. R2 = Carica il puntatore all'inizio del pacchetto (data)
     * 2. LOAD: Carica i primi 64 byte da [R2] dentro ZMM0 (Input A)
     * 3. Avanza il puntatore R2 di 64 byte (punta a Input B)
     * 4. LOAD: Carica i successivi 64 byte da [R2] dentro ZMM1 (Input B)
     * 5. MATH: ZMM0 = ZMM0 + ZMM1 (Somma vettoriale)
     * 6. Avanza il puntatore R2 di altri 64 byte (punta a Output C)
     * 7. STORE: Salva il contenuto di ZMM0 dentro [R2] (Scrive nella RAM)
     * 8. R0 = 42, EXIT
     */
   struct bpf_insn prog[] = {
    // 1. Carica il puntatore 'data' del pacchetto in R2 (Standard eBPF)
    { .code = BPF_LDX | BPF_MEM | BPF_W, .dst_reg = 2, .src_reg = 1, .off = 0, .imm = 0 },

    // 2. Custom LOAD (Input A): ZMM0 = [R2] -> sub_op = 5
    // Il tuo verifier controlla insn->src_reg, quindi R2 va in src_reg. dst_reg è ZMM0.
    { .code = BPF_ALU64 | 0xe0, .dst_reg = 0, .src_reg = 2, .off = 0, .imm = 5 },

    // 3. R2 += 64
    { .code = BPF_ALU64 | BPF_ADD | BPF_K, .dst_reg = 2, .src_reg = 0, .off = 0, .imm = 64 },

    // 4. Custom LOAD (Input B): ZMM1 = [R2] -> sub_op = 5
    { .code = BPF_ALU64 | 0xe0, .dst_reg = 1, .src_reg = 2, .off = 0, .imm = 5 },

    // 5. Custom MATH: ZMM0 = ZMM0 + ZMM1 -> sub_op = 1 (ADD)
    { .code = BPF_ALU64 | 0xe0, .dst_reg = 0, .src_reg = 1, .off = 0, .imm = 1 },

    // 6. R2 += 64
    { .code = BPF_ALU64 | BPF_ADD | BPF_K, .dst_reg = 2, .src_reg = 0, .off = 0, .imm = 64 },

    // 7. Custom STORE (Output C): [R2] = ZMM0 -> sub_op = 6
    // Il tuo verifier controlla insn->dst_reg per il '6', quindi R2 va in dst_reg!
    { .code = BPF_ALU64 | 0xe0, .dst_reg = 2, .src_reg = 0, .off = 0, .imm = 6 },

    // 8. R0 = 42 ed EXIT
    { .code = BPF_ALU64 | BPF_MOV | BPF_K, .dst_reg = 0, .src_reg = 0, .off = 0, .imm = 42 },
    { .code = BPF_JMP | BPF_EXIT, .dst_reg = 0, .src_reg = 0, .off = 0, .imm = 0 }
};
    // Prepariamo i dati reali da passare alla CPU
    struct simd_packet packet;
    memset(&packet, 0, sizeof(packet));

    // Riempiamo Input A e Input B con numeri di prova
    for(int i = 0; i < 16; i++) {
        packet.input_a[i] = i * 10; // 0, 10, 20, 30...
        packet.input_b[i] = 5;      // Fisso 5 per tutti
    }

    union bpf_attr attr;
    memset(&attr, 0, sizeof(attr));
    attr.prog_type = BPF_PROG_TYPE_XDP; // XDP permette l'accesso diretto alla memoria
    attr.insns = (unsigned long)prog;
    attr.insn_cnt = sizeof(prog) / sizeof(struct bpf_insn);
    attr.license = (unsigned long)"GPL";

    char log_buf[4096];
    attr.log_buf = (unsigned long)log_buf;
    attr.log_size = sizeof(log_buf);
    attr.log_level = 1;

    printf("[*] Caricamento del programma nel kernel...\n");
    int prog_fd = syscall(__NR_bpf, BPF_PROG_LOAD, &attr, sizeof(attr));
    if (prog_fd < 0) {
        perror("[-] Errore Verifier");
        printf("LOG:\n%s\n", log_buf);
        return 1;
    }
    printf("[+] Verificatore superato! Compilazione JIT avvenuta.\n");

    // Configurazione per l'esecuzione del test
    union bpf_attr test_attr;
    memset(&test_attr, 0, sizeof(test_attr));
    test_attr.test.prog_fd = prog_fd;
    test_attr.test.data_in = (unsigned long)&packet;
    test_attr.test.data_size_in = sizeof(packet);

    // Diciamo al kernel di riscrivere i dati modificati nello stesso buffer
    test_attr.test.data_out = (unsigned long)&packet;
    test_attr.test.data_size_out = sizeof(packet);

    printf("[*] Prova del fuoco: Esecuzione hardware SIMD nel Kernel...\n");
    int ret = syscall(__NR_bpf, BPF_PROG_TEST_RUN, &test_attr, sizeof(test_attr));
    if (ret < 0) {
        perror("[-] Errore durante l'esecuzione (La CPU ha generato un'eccezione?)");
        close(prog_fd);
        return 1;
    }

    printf("[+] Test Eseguito! Risultato eBPF: %d\n", test_attr.test.retval);
    printf("\n--- VERIFICA DEI RISULTATI NUMERICI SIMD ---\n");

    for(int i = 0; i < 16; i++) {
        printf("Corsia [%02d]: %d + %d = %d ", i, packet.input_a[i], packet.input_b[i], packet.output_c[i]);
        if (packet.output_c[i] == (packet.input_a[i] + packet.input_b[i])) {
            printf("[OK]\n");
        } else {
            printf("[ERRORE - Trovato %d]\n", packet.output_c[i]);
        }
    }

    close(prog_fd);
    return 0;
}
