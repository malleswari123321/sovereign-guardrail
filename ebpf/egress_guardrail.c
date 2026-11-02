#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

SEC("classifier")
int enforce_sovereign_boundary(struct __sk_buff *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return TC_ACT_OK;

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return TC_ACT_OK;

    struct iphdr *iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > data_end)
        return TC_ACT_OK;

    __u32 dest_ip = iph->daddr; // Already in network byte order

    // Convert network byte order to host byte order for bitwise checks
    __u32 host_ip = bpf_ntohl(dest_ip);

    // 1. Allow AWS Mumbai Subnet: 3.5.0.0/16 
    // Network mask for /16 is 0xFFFF0000. Base network: 3.5.0.0 -> 0x03050000
    if ((host_ip & 0xFFFF0000) == 0x03050000) {
        return TC_ACT_OK; // PASS Mumbai
    }

    // 2. Allow AWS Mumbai Edge Subnet: 52.219.0.0/16
    // Base network: 52.219.0.0 -> 0x34DB0000
    if ((host_ip & 0xFFFF0000) == 0x34DB0000) {
        return TC_ACT_OK; // PASS Mumbai Edge
    }

    // Default Policy: DROP unauthorized egress (e.g. US-East 16.x.x.x, 52.217.x.x)
    return TC_ACT_SHOT; 
}

char _license[] SEC("license") = "GPL";
