// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2025 Gogo Business Aviation */

#define __NR_bpf 321

#include <signal.h>
#include <unistd.h>
#include "pjd_tc.skel.h"
// #include "pjd_tc.h"

// #include <linux/bpf.h>
#include <net/if.h>
// #include <sys/syscall.h>
// #include <bpf/bpf_helpers.h>

#define LO_IFINDEX 1
#define ETH_HLEN	14		/* Total octets in header.	 */

// #define IFACE "WAN1IN"	// Apollo
#define IFACE "enp1s0"		// Alma9

struct endp_info {
        __u32 inside_ip;
        __u32 outside_ip;
        __u32 in_count;
        __u32 out_count;
};

static volatile sig_atomic_t exiting = 0;

static void sig_int(int signo)
{
	exiting = 1;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	return vfprintf(stderr, format, args);
}

/*
static void print_endp_info(struct endp_info *endp) {
	printf("endp_infop %p: inside ip %x, outside ip %x, in bytes %d, out bytes %d", endp,
		endp->inside_ip, endp->outside_ip, endp->in_count, endp->out_count);
}

static void print_tc_hook(struct bpf_tc_hook *ptr) {
	fprintf(stderr, "hook: sz: %d, ifindex: %d, attach_point: %d, parent:%d\n", (int)ptr->sz,
		ptr->ifindex, (int)ptr->attach_point, (int)ptr->parent);
}

static void print_tc_opts(struct bpf_tc_opts *ptr) {
	fprintf(stderr, "opts: sz:%d, prog_fd:%d, flags:%x, prog_id:%d, handle:%d, priority:%d, sizeof:%ld\n",
	(int)ptr->sz, (int)ptr->prog_fd, ptr->flags, ptr->prog_id, ptr->handle, ptr->priority, sizeof(struct bpf_tc_opts));
}
*/

long map_callback(struct bpf_map *map, const void *key, void *value, void *ctx) {
	struct endp_info *endp = value;
	printf("inside ip %x, outside ip %x, in bytes %d, out bytes %d", endp->inside_ip,
		endp->outside_ip, endp->in_count, endp->out_count);
	return 0;
}

int main(int argc, char **argv)
{
	DECLARE_LIBBPF_OPTS(bpf_tc_hook, tc_i_hook, .ifindex = LO_IFINDEX,
			    .attach_point = BPF_TC_INGRESS);
	DECLARE_LIBBPF_OPTS(bpf_tc_opts, tc_i_opts, .handle = 1, .flags = BPF_TC_F_REPLACE, .priority = 1);

/*
	DECLARE_LIBBPF_OPTS(bpf_tc_hook, tc_e_hook, .ifindex = LO_IFINDEX,
			    .attach_point = BPF_TC_EGRESS);

	DECLARE_LIBBPF_OPTS(bpf_tc_opts, tc_e_opts, .handle = 2, .priority = 1);
*/

	bool hook_created = false;
	struct pjd_tc_bpf *skel;
	int err;

	libbpf_set_print(libbpf_print_fn);

	// Find the interface IFACE
	unsigned int if_idx = if_nametoindex(IFACE);
        if (if_idx != 0) {
            printf("ifIndex for %s: %u\n", IFACE, if_idx);
        } else {
            perror("if_nametoindex");
        }

	// Set the discovered ifindex in tc_i_hook and tc_e_hook...
	tc_i_hook.ifindex = if_idx;

	skel = pjd_tc_bpf__open_and_load();
	if (!skel) {
		fprintf(stderr, "Failed to open BPF skeleton\n");
		return 1;
	}

	/* The hook (i.e. qdisc) may already exists because:
	 *   1. it is created by other processes or users
	 *   2. or since we are attaching to the TC ingress ONLY,
	 *      bpf_tc_hook_destroy does NOT really remove the qdisc,
	 *      there may be an egress filter on the qdisc
	 */
	err = bpf_tc_hook_create(&tc_i_hook);
	if (!err)
		hook_created = true;

	if (err && err != -EEXIST) {
		fprintf(stderr, "Failed to create ingress TC hook: %d\n", err);
		goto cleanup;
	}

	tc_i_opts.prog_fd = bpf_program__fd(skel->progs.pjd_tc_ingress);
	err = bpf_tc_attach(&tc_i_hook, &tc_i_opts);
	if (err) {
		fprintf(stderr, "Failed to attach ingress TC: %d\n", err);
		goto cleanup;
	}

/*
	err = bpf_tc_hook_create(&tc_e_hook);
	if (err && err != -EEXIST) {
		fprintf(stderr, "Failed to create egress TC hook: %d\n", err);
		goto cleanup;
	}

	tc_e_opts.prog_fd = bpf_program__fd(skel->progs.pjd_tc_egress);
	err = bpf_tc_attach(&tc_e_hook, &tc_e_opts);
	if (err) {
		fprintf(stderr, "Failed to attach egress TC: %d\n", err);
		goto cleanup;
	}
*/

	if (signal(SIGINT, sig_int) == SIG_ERR) {
		err = errno;
		fprintf(stderr, "Can't set signal handler: %s\n", strerror(errno));
		goto cleanup;
	}

	printf("Successfully started! Please run `sudo cat /sys/kernel/debug/tracing/trace_pipe` "
	       "to see output of the BPF program.\n");

	//unsigned int key, prev_key = 0;
	unsigned int key;
	// struct endp_info *endp = NULL;

	sleep(1);
	// if (syscall(__NR_bpf, BPF_MAP_GET_NEXT_KEY, 3, NULL, &prev_key) != 0) {
	if (syscall(__NR_bpf, BPF_MAP_GET_NEXT_KEY, 3, NULL, &key) != 0) {
		while (!exiting) {
			sleep(1);
			union bpf_attr attrs = {
			.map_fd = 3,
			// .key = (unsigned long long)&prev_key,
			.key = (unsigned long long)&key,
			.next_key = (unsigned long long)&key,
			// .value = (long long unsigned int)&endp,
			};

			if (syscall(__NR_bpf, BPF_MAP_GET_NEXT_KEY, &attrs, sizeof(attrs)) != 0) {
				fprintf(stderr, "pjd_tc: nextkey %x NOT found %d\n", key, errno);
				// fprintf(stderr, "pjd_tc: prev_key %x or key %x NOT found %d\n", prev_key, key, errno);
				key = 0;
				continue;
			}
			// fprintf(stderr, "pjd_tc: prev_key %x, key %x found\n", prev_key, key);
			fprintf(stderr, "pjd_tc: key %x found\n", key);

/*
			endp = NULL;
			if (syscall(__NR_bpf, BPF_MAP_LOOKUP_ELEM, &attrs, sizeof(attrs)) != 0) {
				fprintf(stderr, "pjd_tc: Element lookup failed: endp %p ", endp);
				continue;
			}
			if (endp != NULL) {
				print_endp_info(endp);
			}
			prev_key = key;
*/
		}
	}
/*
	while (!exiting) {
                fprintf(stderr, ",");
                sleep(1);
        }
*/

	tc_i_opts.flags = tc_i_opts.prog_fd = 0;
	err = bpf_tc_detach(&tc_i_hook, &tc_i_opts);
	if (err) {
		fprintf(stderr, "Failed to detach TC: %d\n", err);
		goto cleanup;
	}

/*
	err = bpf_tc_detach(&tc_e_hook, &tc_e_opts);
	if (err) {
		fprintf(stderr, "Failed to detach TC: %d\n", err);
		goto cleanup;
	}
	tc_e_opts.flags = tc_e_opts.prog_fd = tc_e_opts.prog_id = 0;
*/


cleanup:
	if (hook_created) {
		bpf_tc_hook_destroy(&tc_i_hook);
	}

	//if (e_hook_created) {
//		bpf_tc_hook_destroy(&tc_e_hook);
	//}
	pjd_tc_bpf__destroy(skel);
	return -err;
}
