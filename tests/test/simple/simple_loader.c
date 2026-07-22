#include <stdio.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

/* Esegue un programma REPEAT volte, ritorna il retval minimo */
static unsigned run_min(int fd, unsigned char *pkt, int len, int reps)
{
    LIBBPF_OPTS(bpf_test_run_opts, opts,
        .data_in = pkt, .data_size_in = len, .repeat = 1);
    unsigned best = ~0u;
    for (int i = 0; i < reps; i++) {
        bpf_prog_test_run_opts(fd, &opts);
        if (opts.retval < best) best = opts.retval;
    }
    return best;
}

int main(void)
{
    struct bpf_object *obj = bpf_object__open_file("simple.bpf.o", NULL);
    if (!obj) { fprintf(stderr, "open fallito\n"); return 1; }
    if (bpf_object__load(obj)) { fprintf(stderr, "load fallito\n"); return 1; }

    int tsc_fd = bpf_program__fd(
        bpf_object__find_program_by_name(obj, "bench_tsc"));
    int kt_fd  = bpf_program__fd(
        bpf_object__find_program_by_name(obj, "bench_ktime"));

    unsigned char pkt[64] = {0};

    printf("BPF_TIME (rdtsc)  : %u cicli\n", run_min(tsc_fd, pkt, 64, 1000));
    printf("bpf_ktime_get_ns  : %u ns\n",    run_min(kt_fd,  pkt, 64, 1000));
    return 0;
}
