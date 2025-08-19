// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2022 Hengqi Chen */
/* #include <vmlinux.h> */

#include <stddef.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_tracing.h>

/* #include "endp_info.h" */

#define TC_ACT_OK 0
#define ETH_P_IP  0x0800 /* Internet Protocol packet    */

#define IP_MF     0x2000
#define IP_OFFSET 0x1FFF

struct endp_info {
    __u32 src_ip;
    __u32 dst_ip;
/*  __u32 src_port; */
/*  __u32 dst_port; */

    __u32 in_count;
    __u32 out_count;
};

struct endp_info_buf {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);
    __type(value, struct endp_info);
} endp_info_buf SEC(".maps");

static inline int ip_is_fragment(struct __sk_buff *skb, __u32 nhoff)
{
    __u16 frag_off;

    bpf_skb_load_bytes(skb, nhoff + offsetof(struct iphdr, frag_off), &frag_off, 2);
    frag_off = __bpf_ntohs(frag_off);
    return frag_off & (IP_MF | IP_OFFSET);
}

SEC("tc")
int tc_ingress(struct __sk_buff *ctx)
{
    void *data_end = (void *)(__u64)ctx->data_end;
    void *data = (void *)(__u64)ctx->data;
    struct ethhdr *l2;
    struct iphdr *l3;
    __u16 tmp16;
    __u32 tmp32;
    __u32 nhoff = ETH_HLEN;

    __u16 ip_proto;
    __u32 dst_addr;
    __u32 src_addr;
    __u32 pkt_len;
    struct endp_info_buf *endpi;

    if (ctx->protocol != bpf_htons(ETH_P_IP))
        return TC_ACT_OK;

    /* Ignore fragments */
    if (ip_is_fragment(ctx, nhoff))
                return TC_ACT_OK;

    l2 = data;
    if ((void *)(l2 + 1) > data_end)
        return TC_ACT_OK;

    l3 = (struct iphdr *)(l2 + 1);
    if ((void *)(l3 + 1) > data_end)
        return TC_ACT_OK;

    bpf_skb_load_bytes(ctx, nhoff + offsetof(struct iphdr, protocol), &tmp16, 1);
    ip_proto = bpf_ntohs(tmp16);

    bpf_skb_load_bytes(ctx, nhoff + offsetof(struct iphdr, saddr), &(tmp32), 4);
    src_addr = bpf_ntohl(tmp32);
    bpf_skb_load_bytes(ctx, nhoff + offsetof(struct iphdr, daddr), &(tmp32), 4);
    dst_addr = bpf_ntohl(tmp32);
    pkt_len = bpf_ntohs(l3->tot_len);

    /* map key is the EXTERNAL address */
    endpi = bpf_map_lookup_elem(&endp_info_buf, &src_addr);
    if (endpi == NULL) {
        if (bpf_map_update_elem(&endp_info_buf, &src_addr, &endpi, BPF_NOEXIST) != 0) {
            /* whine */
            return TC_ACT_OK;
        }
    }
    if (endpi == NULL) {
        /* whine */
        return TC_ACT_OK;
    }

    /* REALLY should be a map of a map of INTERNAL addrs... */
    endpi->value->dst_ip = dst_addr;
    endpi->value->in_count += pkt_len;

    bpf_printk("tc_ingress: Got IP packet: tot_len: %d, ttl: %d", bpf_ntohs(l3->tot_len), l3->ttl);
    return TC_ACT_OK;
}

SEC("tc")
int tc_egress(struct __sk_buff *ctx)
{
    void *data_end = (void *)(__u64)ctx->data_end;
    void *data = (void *)(__u64)ctx->data;
    struct ethhdr *l2;
    struct iphdr *l3;
    __u16 tmp16;
    __u32 tmp32;
    __u32 nhoff = ETH_HLEN;

    __u16 ip_proto;
    __u32 dst_addr;
    __u32 src_addr;
    __u32 pkt_len;
    struct endp_info_buf *endpi;

    if (ctx->protocol != bpf_htons(ETH_P_IP))
        return TC_ACT_OK;

    /* Ignore fragments */
    if (ip_is_fragment(ctx, nhoff))
        return TC_ACT_OK;

    l2 = data;
    if ((void *)(l2 + 1) > data_end)
        return TC_ACT_OK;

    l3 = (struct iphdr *)(l2 + 1);
    if ((void *)(l3 + 1) > data_end)
        return TC_ACT_OK;

    bpf_skb_load_bytes(ctx, nhoff + offsetof(struct iphdr, protocol), &tmp16, 1);
    ip_proto = bpf_ntohs(tmp16);

    bpf_skb_load_bytes(ctx, nhoff + offsetof(struct iphdr, saddr), &(tmp32), 4);
    src_addr = bpf_ntohl(tmp32);
    bpf_skb_load_bytes(ctx, nhoff + offsetof(struct iphdr, daddr), &(tmp32), 4);
    dst_addr = bpf_ntohl(tmp32);
    pkt_len = bpf_ntohs(l3->tot_len);

    /* map key is the EXTERNAL address */
    endpi = bpf_map_lookup_elem(&endp_info_buf, &dst_addr);
    if (endpi == NULL) {
        if (bpf_map_update_elem(&endp_info_buf, &dst_addr, &endpi, BPF_NOEXIST) != 0) {
            /* whine */
            return TC_ACT_OK;
        }
    }
    if (endpi == NULL) {
        /* whine */
        return TC_ACT_OK;
    }

    /* REALLY should be a map of a map of INTERNAL addrs... */
    endpi->value->src_ip = src_addr;
    endpi->value->in_count += pkt_len;

    bpf_printk("tc_egress: Got IP packet: tot_len: %d, ttl: %d", bpf_ntohs(l3->tot_len), l3->ttl);
    return TC_ACT_OK;
}

char __license[] SEC("license") = "GPL";
