#ifndef RTPENGINE_VMLINUX_STUB_H
#define RTPENGINE_VMLINUX_STUB_H

typedef unsigned char __u8;
typedef unsigned short __u16;
typedef unsigned int __u32;
typedef unsigned long long __u64;
typedef __u16 __be16;
typedef __u32 __be32;

#define __uint(name, val) int (*name)[val]
#define __type(name, val) typeof(val) *name

#define SEC(name) __attribute__((section(name), used))

#ifndef BPF_MAP_TYPE_HASH
#define BPF_MAP_TYPE_HASH 1
#endif

#ifndef ETH_P_IP
#define ETH_P_IP 0x0800
#endif

#ifndef IPPROTO_UDP
#define IPPROTO_UDP 17
#endif

#ifndef TC_ACT_OK
#define TC_ACT_OK 0
#define TC_ACT_SHOT 2
#endif

#ifndef BPF_F_PSEUDO_HDR
#define BPF_F_PSEUDO_HDR (1ULL << 4)
#endif

struct ethhdr {
	__u8 h_dest[6];
	__u8 h_source[6];
	__be16 h_proto;
};

struct iphdr {
#if defined(__LITTLE_ENDIAN_BITFIELD) || __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
	__u8 ihl:4,
	     version:4;
#else
	__u8 version:4,
	     ihl:4;
#endif
	__u8 tos;
	__be16 tot_len;
	__be16 id;
	__be16 frag_off;
	__u8 ttl;
	__u8 protocol;
	__be16 check;
	__be32 saddr;
	__be32 daddr;
};

struct udphdr {
	__be16 source;
	__be16 dest;
	__be16 len;
	__be16 check;
};

struct __sk_buff {
	__u32 len;
	__u32 pkt_type;
	__u32 mark;
	__u32 queue;
	__u32 priority;
	__u32 ingress_ifindex;
	__u32 ifindex;
	__u32 tc_index;
	__u32 cb[5];
	__u32 hash;
	__u32 tc_classid;
	__u32 data;
	__u32 data_end;
	__u32 napi_id;
	__u32 family;
};

#ifndef offsetof
#define offsetof(type, member) __builtin_offsetof(type, member)
#endif

#endif
