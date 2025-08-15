/* Copyright 2025 Gogo Business Aviation */

#ifndef __pjd_tc_h__
#define __pjd_tc_h__

#ifndef __u32
#define __u32 long
#endif

struct endp_info {
        __u32 src_ip;
        __u32 dst_ip;
        __u32 in_count;
        __u32 out_count;
};

#endif
