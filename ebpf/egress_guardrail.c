#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/pkt_cls.h>  // <-- Add this line for TC_ACT_OK and TC_ACT_SHOT
#include <bpf/bpf_helpers.h>

// BPF map containing approved sovereign destination CIDRs / Subnet IPs
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);   // Destination IPv4 address
    __type(value, __u8);  // 1 = Approved, 0 = Blocked
} sovereign_ip_map SEC(".maps");

SEC("tc_egress")
int enforce_sovereign_boundary(struct __sk_buff *skb) {
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return TC_ACT_OK;

    if (eth->h_proto != __constant_htons(ETH_P_IP))
        return TC_ACT_OK;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return TC_ACT_OK;

    __u32 dest_ip = ip->daddr;
    __u8 *is_approved = bpf_map_lookup_elem(&sovereign_ip_map, &dest_ip);

    // If destination IP is not in sovereign map, drop packet at kernel layer
    if (!is_approved || *is_approved == 0) {
        bpf_printk("[SOVEREIGN VIOLATION] Dropped egress packet to foreign IP: %x\n", dest_ip);
        return TC_ACT_SHOT; // Drop packet immediately
    }

    return TC_ACT_OK; // Allow packet
}

char _license[] SEC("license") = "GPL";
