#include <linux/bpf.h>
#include <linux/bpf_halpers.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>

SEC("xdp")
int parse_package(struct xdp_md *c){

}

char _license[] SEC("license") = "GPL";
