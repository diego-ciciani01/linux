#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <linux/bpf.h>

/* Definiamo la macro per la nostra istruzione custom eBPF SIMD.
 * Il codice dell'istruzione sarà 0xe0 (il tuo BPF_SIMD) combinato con BPF_ALU64 (0x07).
 * Quindi insn->code sarà 0xe7.
 */
#define BPF_SIMD_INSN(IMM, DST, SRC, OFF)          \
    ((struct bpf_insn) {                            \
        .code    = 0xe0 | 0x07, /* BPF_SIMD | BPF_ALU64 */ \
        .dst_reg = DST,                             \
        .src_reg = SRC,                             \
        .off     = OFF,                             \
        .imm     = IMM                              \
    })

/* Macro standard helper per eBPF (se non incluse da linux/bpf.h) */
#define BPF_MOV64_IMM(DST, IMM)                     \
    ((struct bpf_insn) {                            \
        .code    = 0xb7, /* BPF_ALU64 | BPF_MOV | BPF_K */ \
        .dst_reg = DST,                             \
        .src_reg = 0,                               \
        .off     = 0,                               \
        .imm     = IMM                              \
    })

#define BPF_EXIT_INSN()                             \
    ((struct bpf_insn) {                            \
        .code    = 0x95, /* BPF_JMP | BPF_EXIT */   \
        .dst_reg = 0,                               \
        .src_reg = 0,                               \
        .off     = 0,                               \
        .imm     = 0                                \
    })

int main() {
    /* Creiamo un programma eBPF di test di sole 3 istruzioni:
     * 1. Eseguiamo uno XOR parallelo (imm=4) tra ZMM0 e ZMM1.
     * Questa istruzione tocca solo i registri interni della CPU,
     * quindi è sicurissima per un primo test (non tocca la memoria).
     * 2. Carichiamo il valore 42 nel registro R0 (il valore di ritorno).
     * 3. Usciamo.
     */
struct bpf_insn prog[] = {
    // 1. XOR custom: ZMM2 = ZMM2 XOR ZMM3 (imm = 4)
    { .code = 0xe7, .dst_reg = 2, .src_reg = 3, .off = 0, .imm = 4 },

    // 2. NUOVA SOMMA custom: ZMM4 = ZMM4 + ZMM5 (imm = 1)
    { .code = 0xe7, .dst_reg = 4, .src_reg = 8, .off = 0, .imm = 1 },

    // 3. Carichiamo 42 in R0 per l'uscita
    { .code = BPF_ALU64 | BPF_MOV | BPF_K, .dst_reg = BPF_REG_0, .src_reg = 0, .off = 0, .imm = 42 },

    // 4. Exit
    { .code = BPF_JMP | BPF_EXIT, .dst_reg = 0, .src_reg = 0, .off = 0, .imm = 0 }
};
    union bpf_attr attr;
    memset(&attr, 0, sizeof(attr));

    attr.prog_type = BPF_PROG_TYPE_SOCKET_FILTER; /* Tipo semplice per i test */
    attr.insns = (unsigned long)prog;
    attr.insn_cnt = sizeof(prog) / sizeof(struct bpf_insn);
    attr.license = (unsigned long)"GPL";

    char log_buf[4096];
    attr.log_buf = (unsigned long)log_buf;
    attr.log_size = sizeof(log_buf);
    attr.log_level = 1; // Chiediamo al verifier di essere logorroico

    printf("[*] Caricamento del programma eBPF con istruzione SIMD...\n");
    int prog_fd = syscall(__NR_bpf, BPF_PROG_LOAD, &attr, sizeof(attr));

    if (prog_fd < 0) {
        perror("[-] Errore nel caricamento del programma (Verifier fallito)");
        printf("--- LOG DEL VERIFICATORE ---\n%s\n", log_buf);
        return 1;
    }
    printf("[+] Programma accettato dal Verificatore! FD: %d\n", prog_fd);
    printf("Sleep for 10 seconds\n");
    sleep(10);
    /* Ora eseguiamo il programma usando BPF_PROG_TEST_RUN */
    union bpf_attr test_attr;
    memset(&test_attr, 0, sizeof(test_attr));
    test_attr.test.prog_fd = prog_fd;

    // Passiamo un array vuoto come finto pacchetto dati, giusto per attivare l'esecuzione
    char dummy_packet[64] = {0};
    test_attr.test.data_in = (unsigned long)dummy_packet;
    test_attr.test.data_size_in = sizeof(dummy_packet);

    printf("[*] Esecuzione del programma nel kernel...\n");
    int ret = syscall(__NR_bpf, BPF_PROG_TEST_RUN, &test_attr, sizeof(test_attr));

    if (ret < 0) {
        perror("[-] Errore durante l'esecuzione del TEST_RUN");
        return 1;
    }

    printf("[+] Test completato con successo!\n");
    printf("[+] Il programma eBPF ha restituito il valore: %d (Atteso: 42)\n", test_attr.test.retval);

    close(prog_fd);
    return 0;
}
