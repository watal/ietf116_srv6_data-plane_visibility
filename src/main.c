#define KBUILD_MODNAME "foo"
#include <stdbool.h>
#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/udp.h>
#include <linux/seg6.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "xdp_map.h"

SEC("xdp")
int xdp_prog(struct xdp_md *ctx) {
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	__u32 probe_key = XDP_PASS; /* XDP_PASS = 2 */
	struct ethhdr *eth = data;

    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto != bpf_htons(ETH_P_IPV6))
        return XDP_PASS;

    struct ipv6hdr *ipv6 = (void *)(eth + 1);
    if ((void *)(ipv6 + 1) > data_end)
        return XDP_PASS;

    // is srv6
   if (ipv6->nexthdr != IPPROTO_IPV6ROUTE)
        return XDP_PASS;

    struct ipv6_rt_hdr *rt_hdr = (void *)(ipv6 + 1);
    if ((void *)(rt_hdr + 1) > data_end)
        return XDP_PASS;

    if (rt_hdr->type != IPV6_SRCRT_TYPE_4)
        return XDP_PASS;

    struct probe_data key = {};
    __u64 zero = 0, *value;
    __builtin_memcpy(&key.h_source, &eth->h_source, ETH_ALEN);
    __builtin_memcpy(&key.h_dest, &eth->h_dest, ETH_ALEN);
    key.h_proto = eth->h_proto;
    key.v6_srcaddr = ipv6->saddr;
    key.v6_dstaddr = ipv6->daddr;

    value = bpf_map_lookup_elem(&ipfix_probe_map, &key);
    if (!value) {
        bpf_map_update_elem(&ipfix_probe_map, &key, &zero, BPF_NOEXIST);
        value = bpf_map_lookup_elem(&ipfix_probe_map, &key);
        if (!value)
            return XDP_PASS;
    }
    (*value)++;

	return XDP_PASS;
}

char _license[] SEC("license") = "MIT";