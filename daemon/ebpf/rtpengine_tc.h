#ifndef RTPENGINE_TC_H
#define RTPENGINE_TC_H

#ifdef __BPF__
#include <linux/types.h>
#else
#include <stdint.h>
#endif

#define RTPENGINE_TC_MAX_FLOWS 65536

#define RTPENGINE_TC_AF_INET  2
#define RTPENGINE_TC_AF_INET6 10

struct rtpengine_tc_addr {
	uint32_t family;
	uint16_t port;
	uint16_t pad;
	union {
		uint32_t ipv4;
		uint8_t  ipv6[16];
		uint32_t u32[4];
	} u;
};

struct rtpengine_tc_key {
	struct rtpengine_tc_addr local;
};

struct rtpengine_tc_flow {
	struct rtpengine_tc_addr expected_src;
	struct rtpengine_tc_addr src;
	struct rtpengine_tc_addr dst;
	uint32_t ifindex;
	uint32_t flags;
	uint64_t packets;
	uint64_t bytes;
};

#define RTPENGINE_TC_F_CHECK_SRC  (1u << 0)

#endif
