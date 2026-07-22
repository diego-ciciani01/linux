#include <stdio.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <bpf/libbpf.h>
#include <linux/if_link.h>
#include <net/if.h>


int main(void)
{
    /* Open and uppload the pre-compiled bpf object */
    struct bpf_object *obj = bpf_object__open("/bin/test_rdtsc/rdtsc.bpf.o");
    if (!obj) {
        perror("FAIL: open");
        return 1;
    }

    if (bpf_object__load(obj)){
        perror("FAIL: load");
        return 1;
    }
    printf("OK: loaded program \n");

    /* Get back the file descriptor form the map */
    int prog_fd = bpf_program__fd(
        bpf_object__find_program_by_name(obj, "rdtsc_prog"));

    int map_fd = bpf_map__fd(
        bpf_object__find_map_by_name(obj, "tsc_map"));

    /* Attacch to socket UDP */
    int ifindex = if_nametoindex("lo");
    if (!ifindex){
        perror("FAIL: if_nametoindex");
        return 1;
    }
    if (bpf_xdp_attach(ifindex, prog_fd, XDP_FLAGS_SKB_MODE, NULL) < 0) {
        perror("FAIL: bpf_xdp_attach \n");
        return 1;
    }

    printf("OK: Program attached via xdp\n");

    /*Create the tirgger*/
    int tx = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in addr = {
        .sin_family      = AF_INET,
        .sin_port        = htons(9999),
        .sin_addr.s_addr = htonl(INADDR_LOOPBACK),
    };
    char pkt[] = "trigger";
    sendto(tx, pkt, sizeof(pkt), 0, (struct sockaddr *)&addr, sizeof(addr));
    close(tx);
    usleep(100000);

    /* Read from maps  */
    __u32 key = 0;
    __u64 tsc = 0;
    bpf_map_lookup_elem(map_fd, &key, &tsc);

    if (tsc == 0) {
        printf("FAIL: TSC = 0\n");
        bpf_xdp_detach(ifindex, XDP_FLAGS_SKB_MODE, NULL);
        return 1;
    }
    printf("OK rdtsc (XDP) = %llu loops\n", tsc);
\
    /* remove XDP */
    bpf_xdp_detach(ifindex, XDP_FLAGS_SKB_MODE, NULL);
    bpf_object__close(obj);
    return 0;
}
