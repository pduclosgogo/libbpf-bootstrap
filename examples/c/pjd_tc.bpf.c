// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2022 Hengqi Chen */

#define __x86_64__

#include <vmlinux.h>
/*
#include <stddef.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
*/
#include <unistd.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_tracing.h>

#define TC_ACT_OK 0
#define ETH_P_IP  0x0800 /* Internet Protocol packet    */
#define ETH_HLEN	14		/* Total octets in header.	 */

#define IP_MF     0x2000
#define IP_OFFSET 0x1FFF

struct endp_info {
        __u32 inside_ip;
        __u32 in_b_count;
        __u32 in_p_count;
        __u32 outside_ip;
        __u32 out_b_count;
        __u32 out_p_count;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, __u32);
    __type(value, struct endp_info);
} endp_info_buf SEC(".maps");

/*
static inline int ip_is_fragment(struct __sk_buff *skb, __u32 nhoff)
{
    __u16 frag_off;

    bpf_skb_load_bytes(skb, nhoff + offsetof(struct iphdr, frag_off), &frag_off, 2);
    frag_off = __bpf_ntohs(frag_off);
    return frag_off & (IP_MF | IP_OFFSET);
}
*/

SEC("tc")
int pjd_tc_ingress(struct __sk_buff *ctx)
{
    void *data_end = (void *)(__u64)ctx->data_end;
    void *data = (void *)(__u64)ctx->data;
    struct ethhdr *l2;
    struct iphdr *l3;
    struct endp_info *infop = NULL;
    __u32 tmp32;

    if (ctx->protocol != bpf_htons(ETH_P_IP))
        return TC_ACT_OK;

    l2 = data;
    if ((void *)(l2 + 1) > data_end)
        return TC_ACT_OK;

    l3 = (struct iphdr *)(l2 + 1);
    if ((void *)(l3 + 1) > data_end)
        return TC_ACT_OK;

    bpf_skb_load_bytes(ctx, ETH_HLEN + offsetof(struct iphdr, saddr), &tmp32, 4);
    tmp32 = bpf_ntohl(tmp32);

    // map key is the EXTERNAL address
    infop = bpf_map_lookup_elem(&endp_info_buf, &tmp32);
    if (infop) {
	if (infop->outside_ip != tmp32) {
        	bpf_printk("pjd_tc_ingress: mismatch infop->out_ip %lx & tmp32 %lx", infop->outside_ip, tmp32);  // DEBUG
	}
        bpf_skb_load_bytes(ctx, ETH_HLEN + offsetof(struct iphdr, daddr), &tmp32, 4);
        tmp32 = bpf_ntohl(tmp32);
        infop->inside_ip = tmp32;
	if (infop->in_b_count == 0) {
        	bpf_printk("pjd_tc_ingress: Found infop %p for outside_ip %lx, in_b_count %d",
			infop, infop->outside_ip, infop->in_b_count);   // DEBUG
	} else if ((infop->in_p_count % 10) == 0) {
        	bpf_printk("pjd_tc_ingress: Found infop %p for outside_ip %lx, in_b_count %d, in_p_count %d",
			infop, infop->outside_ip, infop->in_b_count, infop->in_p_count);   // DEBUG
	}
        infop->in_b_count += bpf_ntohs(l3->tot_len);
        infop->in_p_count += 1;
    } else {
        struct endp_info init_val = {tmp32, 0, 0, 0};
        init_val.outside_ip = tmp32;
        bpf_skb_load_bytes(ctx, ETH_HLEN + offsetof(struct iphdr, daddr), &tmp32, 4);
        tmp32 = bpf_ntohl(tmp32);
        init_val.inside_ip = tmp32;
        init_val.in_b_count += bpf_ntohs(l3->tot_len);
        init_val.in_p_count = 1;
        tmp32 = init_val.outside_ip;
        bpf_map_update_elem(&endp_info_buf, &tmp32, &init_val, BPF_ANY);
        bpf_printk("pjd_tc_ingress: No map found for %lx", init_val.outside_ip);  // DEBUG
        return TC_ACT_OK;
    }

    // bpf_printk("pjd_tc_ingress: Got IP packet: tot_len: %d, ttl: %d", bpf_ntohs(l3->tot_len), l3->ttl);
    return TC_ACT_OK;
}

SEC("tc")
int pjd_tc_egress(struct __sk_buff *ctx)
{
    void *data_end = (void *)(__u64)ctx->data_end;
    void *data = (void *)(__u64)ctx->data;
    struct ethhdr *l2;
    struct iphdr *l3;
    struct endp_info *infop = NULL;
    __u32 tmp32;

    if (ctx->protocol != bpf_htons(ETH_P_IP))
        return TC_ACT_OK;

    l2 = data;
    if ((void *)(l2 + 1) > data_end)
        return TC_ACT_OK;

    l3 = (struct iphdr *)(l2 + 1);
    if ((void *)(l3 + 1) > data_end)
        return TC_ACT_OK;

    // map key is the EXTERNAL address
    bpf_skb_load_bytes(ctx, ETH_HLEN + offsetof(struct iphdr, daddr), &tmp32, 4);
    tmp32 = bpf_ntohl(tmp32);

    infop = bpf_map_lookup_elem(&endp_info_buf, &tmp32);
    if (infop) {
	if (infop->outside_ip != tmp32) {
        	bpf_printk("pjd_tc_egress: mismatch infop->out_ip %lx & tmp32 %lx", infop->outside_ip, tmp32);  // DEBUG
	}
        bpf_skb_load_bytes(ctx, ETH_HLEN + offsetof(struct iphdr, saddr), &tmp32, 4);
        tmp32 = bpf_ntohl(tmp32);
        infop->inside_ip = tmp32;
	if (infop->out_b_count == 0) {
        	bpf_printk("pjd_tc_egress: Found infop %p for inside_ip %lx, out_b_count %d", infop, tmp32, infop->out_b_count); // DEBUG
	} else if ((infop->out_p_count % 10) == 0) {
        	bpf_printk("pjd_tc_egress: Found infop %p for inside_ip %lx, out_b_count %d, out_p_count %d",
			infop, tmp32, infop->out_b_count, infop->out_p_count); // DEBUG
	}
        infop->out_b_count += bpf_ntohs(l3->tot_len);
        infop->out_p_count += 1;
    } else {
        struct endp_info init_val = {tmp32, 0, 0, 0};
        init_val.outside_ip = tmp32;
        bpf_skb_load_bytes(ctx, ETH_HLEN + offsetof(struct iphdr, saddr), &tmp32, 4);
        tmp32 = bpf_ntohl(tmp32);
        init_val.inside_ip = tmp32;
        init_val.out_b_count += bpf_ntohs(l3->tot_len);
        init_val.out_p_count = 1;
        tmp32 = init_val.outside_ip;
        bpf_map_update_elem(&endp_info_buf, &tmp32, &init_val, BPF_ANY);
        bpf_printk("pjd_tc_egress: No map found for %lx", init_val.outside_ip);   // DEBUG
        return TC_ACT_OK;
    }

    // bpf_printk("pjd_tc_egress: Got IP packet: tot_len: %d, ttl: %d", bpf_ntohs(l3->tot_len), l3->ttl);
    return TC_ACT_OK;
}


char __license[] SEC("license") = "GPL";
