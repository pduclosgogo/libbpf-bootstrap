// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2022 Hengqi Chen */

#include <vmlinux.h>
/*
#include <stddef.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
*/
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_tracing.h>

#include "pjd_tc.h"

#define TC_ACT_OK 0
#define ETH_P_IP  0x0800 /* Internet Protocol packet    */

#define IP_MF     0x2000
#define IP_OFFSET 0x1FFF

/*
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
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
*/

SEC("tc")
int tc_ingress(struct __sk_buff *ctx)
{
    void *data_end = (void *)(__u64)ctx->data_end;
    void *data = (void *)(__u64)ctx->data;
    struct ethhdr *l2;
    struct iphdr *l3;
    // struct endp_info *infop;
    // __u32 tmp32;

    if (ctx->protocol != bpf_htons(ETH_P_IP))
        return TC_ACT_OK;

/*
    // Ignore fragments
    if (ip_is_fragment(ctx, ETH_HLEN))
        return TC_ACT_OK;
*/

    l2 = data;
    if ((void *)(l2 + 1) > data_end)
        return TC_ACT_OK;

    l3 = (struct iphdr *)(l2 + 1);
    if ((void *)(l3 + 1) > data_end)
        return TC_ACT_OK;

/*
    // map key is the EXTERNAL address
    bpf_skb_load_bytes(ctx, ETH_HLEN + offsetof(struct iphdr, saddr), &tmp32, 4);
    tmp32 = bpf_ntohl(tmp32);

    infop = bpf_map_lookup_elem(&endp_info_buf, &tmp32);
    if (infop) {
        if (infop->outside_ip != tmp32) {
            bpf_printk("pjd_tc_ingress: Mismatch between key %lx and outside_ip %lx", tmp32, infop->outside_ip);   // DEBUG
            return TC_ACT_OK;
        }

        bpf_skb_load_bytes(ctx, ETH_HLEN + offsetof(struct iphdr, daddr), &tmp32, 4);
        tmp32 = bpf_ntohl(tmp32);
        infop->inside_ip = tmp32;
        infop->in_count += bpf_ntohs(l3->tot_len);
        bpf_printk("pjd_tc_ingress: Found %p for %lx", infop, tmp32);   // DEBUG
    } else {
        struct endp_info init_val = {tmp32, 0, 0, 0};
        bpf_printk("pjd_tc_ingress: No map found for %lx", tmp32);  // DEBUG

        init_val.outside_ip = tmp32;
        bpf_skb_load_bytes(ctx, ETH_HLEN + offsetof(struct iphdr, daddr), &tmp32, 4);
        tmp32 = bpf_ntohl(tmp32);
        init_val.inside_ip = tmp32;
        init_val.in_count += bpf_ntohs(l3->tot_len);
        tmp32 = init_val.outside_ip;
        bpf_map_update_elem(&endp_info_buf, &tmp32, &init_val, BPF_ANY);
        return TC_ACT_OK;
    }
*/

    bpf_printk("pjd_tc_ingress: Got IP packet: tot_len: %d, ttl: %d", bpf_ntohs(l3->tot_len), l3->ttl);
    return TC_ACT_OK;
}

/*
SEC("tc")
int pjd_tc_egress(struct __sk_buff *ctx)
{
    void *data_end = (void *)(__u64)ctx->data_end;
    void *data = (void *)(__u64)ctx->data;
    struct ethhdr *l2;
    struct iphdr *l3;
    __u32 tmp32;
    struct endp_info *infop;
    struct endp_info init_val = {};

    if (ctx->protocol != bpf_htons(ETH_P_IP))
        return TC_ACT_OK;

    //
    if (ip_is_fragment(ctx, ETH_HLEN))
        return TC_ACT_OK;

    l2 = data;
    if ((void *)(l2 + 1) > data_end)
        return TC_ACT_OK;

    l3 = (struct iphdr *)(l2 + 1);
    if ((void *)(l3 + 1) > data_end)
        return TC_ACT_OK;

    //
    bpf_skb_load_bytes(ctx, ETH_HLEN + offsetof(struct iphdr, daddr), &tmp32, 4);
    tmp32 = bpf_ntohl(tmp32);

    infop = bpf_map_lookup_elem(&endp_info_buf, &tmp32);
    if (infop) {
        if (infop->outside_ip != tmp32) {
            bpf_printk("pjd_tc_egress: Mismatch between key %lx and outside_ip %lx", tmp32, infop->outside_ip);   // DEBUG
            return TC_ACT_OK;
        }
        bpf_skb_load_bytes(ctx, ETH_HLEN + offsetof(struct iphdr, saddr), &tmp32, 4);
        tmp32 = bpf_ntohl(tmp32);
        infop->inside_ip = tmp32;
        infop->out_count += bpf_ntohs(l3->tot_len);
        bpf_printk("pjd_tc_egress: Found %p for %lx, count", infop, tmp32); // DEBUG
    } else {
        struct endp_info init_val = {tmp32, 0, 0, 0};
        bpf_printk("pjd_tc_egress: No map found for %lx", tmp32);   // DEBUG
        init_val.inside_ip = tmp32;

        bpf_skb_load_bytes(ctx, ETH_HLEN + offsetof(struct iphdr, saddr), &tmp32, 4);
        tmp32 = bpf_ntohl(tmp32);
        init_val.inside_ip = tmp32;
        init_val.out_count += bpf_ntohs(l3->tot_len);
        tmp32 = init_val.inside_ip;
        bpf_map_update_elem(&endp_info_buf, &tmp32, &init_val, BPF_ANY);
        return TC_ACT_OK;
    }

    bpf_printk("pjd_tc_egress: Got IP packet: tot_len: %d, ttl: %d", bpf_ntohs(l3->tot_len), l3->ttl);
    return TC_ACT_OK;
}
*/

char __license[] SEC("license") = "GPL";
