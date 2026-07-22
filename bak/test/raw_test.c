nclude <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <linux/bpf.h>

// Macro per creare una istruzione BPF "cruda" a mano
// #define BPF_RAW_INSN(CODE, DST, SRC, OFF, IMM) \
//     ((struct bpf_insn) { \
//             .code = CODE, \
//                     .dst_reg = DST, \
//                             .src_reg = SRC, \
//                                     .off = OFF, \
//                                             .imm = IMM })
//
//                                             int main() {
//                                                 printf("Provo a caricare l'opcode custom 0xe0 nel kernel...\n");
//
//                                                     // Definiamo il nostro micro-programma eBPF istruzione per istruzione
//                                                         struct bpf_insn prog[] = {
//                                                                 // 1. R0 = 0 (imposta il valore di ritorno di default a 0)
//                                                                         BPF_RAW_INSN(0xb7, 0, 0, 0, 0),
//
//                                                                                 // 2. LA TUA ISTRUZIONE CUSTOM (Opcode 0xe0)
//                                                                                         // Se la tua istruzione legge dei registri specifici o usa un valore immediato,
//                                                                                                 // cambieremo gli '0' con i valori corretti.
//                                                                                                         BPF_RAW_INSN(0xe0, 0, 0, 0, 0),
//
//                                                                                                                 // 3. EXIT (Termina il programma BPF)
//                                                                                                                         BPF_RAW_INSN(0x95, 0, 0, 0, 0),
//                                                                                                                             };
//
//                                                                                                                                 // Prepariamo gli attributi per la syscall
//                                                                                                                                     union bpf_attr attr = {
//                                                                                                                                             .prog_type = BPF_PROG_TYPE_SOCKET_FILTER, // Un tipo di programma base
//                                                                                                                                                     .insns = (uint64_t)prog,                  // Puntatore alle nostre istruzioni
//                                                                                                                                                             .insn_cnt = sizeof(prog) / sizeof(prog[0]), // Numero di istruzioni
//                                                                                                                                                                     .license = (uint64_t)"GPL",               // Richiesto dal kernel
//                                                                                                                                                                         };
//
//                                                                                                                                                                             // Chiamata diretta alla syscall BPF (nessuna libreria esterna!)
//                                                                                                                                                                                 int fd = syscall(__NR_bpf, BPF_PROG_LOAD, &attr, sizeof(attr));
//
//                                                                                                                                                                                         if (fd < 0) {
//                                                                                                                                                                                                 perror("ERRORE! Il kernel (o il verifier) ha rifiutato l'istruzione");
//                                                                                                                                                                                                         return 1;
//                                                                                                                                                                                                             }
//
//                                                                                                                                                                                                                 printf("SUCCESSO! Programma caricato. Il kernel riconosce l'opcode 0xe0!\n");
//                                                                                                                                                                                                                     close(fd);
//                                                                                                                                                                                                                         return 0;
//                                                                                                                                                                                                                         }
