#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <net/if.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

static int ifindex = 0;

// Funzione di pulizia per staccare il programma eBPF
void handle_sig(int sig) {
    printf("\n[User] Rimozione del programma XDP dall'interfaccia...\n");
    if (ifindex > 0) {
        // In libbpf 0.5.0 si usa bpf_set_link_xdp_fd con -1 come FD per fare il detach
        bpf_set_link_xdp_fd(ifindex, -1, 0);
    }
    exit(0);
}

int main(int argc, char **argv) {
    struct bpf_object *obj;
    struct bpf_program *prog;
    int prog_fd;
    const char *ifname = "lo";

    if (argc > 1) {
        ifname = argv[1];
    }

    ifindex = if_nametoindex(ifname);
    if (ifindex == 0) {
        fprintf(stderr, "Errore: Interfaccia %s non trovata\n", ifname);
        return 1;
    }

    signal(SIGINT, handle_sig);
    signal(SIGTERM, handle_sig);

    printf("[User] Apertura del file eBPF...\n");

    // In libbpf 0.5.0 l'apertura e il caricamento sono separati
    obj = bpf_object__open_file("xdp_time.bpf.o", NULL);
    long err = libbpf_get_error(obj);
    if (err) {
        fprintf(stderr, "Errore: Impossibile aprire l'oggetto eBPF (%ld)\n", err);
        return 1;
    }

    printf("[User] Caricamento del programma eBPF nel kernel...\n");
    if (bpf_object__load(obj)) {
        fprintf(stderr, "Errore: Impossibile caricare l'oggetto eBPF nel kernel\n");
        bpf_object__close(obj);
        return 1;
    }

    // Trova il programma nell'oggetto ELF
    prog = bpf_object__find_program_by_name(obj, "xdp_time_prog");
    if (!prog) {
        fprintf(stderr, "Errore: Funzione xdp_time_prog non trovata\n");
        bpf_object__close(obj);
        return 1;
    }

    // Ottieni il File Descriptor
    prog_fd = bpf_program__fd(prog);
    if (prog_fd < 0) {
        fprintf(stderr, "Errore: FD del programma non valido\n");
        bpf_object__close(obj);
        return 1;
    }

    printf("[User] Aggancio XDP su interfaccia: %s (index: %d)\n", ifname, ifindex);
    // In libbpf 0.5.0 si usa bpf_set_link_xdp_fd per agganciare il programma all'interfaccia
    int ret = bpf_set_link_xdp_fd(ifindex, prog_fd, 0);
    if (ret < 0) {
        fprintf(stderr, "Errore nell'aggancio XDP: %d\n", ret);
        bpf_object__close(obj);
        return 1;
    }

    printf("[User] Successo! Il programma eBPF è attivo. Premi Ctrl+C per uscire.\n");

    while (1) {
        sleep(1);
    }

    return 0;
}
