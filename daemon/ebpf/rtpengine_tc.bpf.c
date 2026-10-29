#define __BPF__ 1

#include "vmlinux_stub.h"
#include "rtpengine_tc.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

char LICENSE[] SEC("license") = "GPL";

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, RTPENGINE_TC_MAX_FLOWS);
	__type(key, struct rtpengine_tc_key);
	__type(value, struct rtpengine_tc_flow);
} flows SEC(".maps");

static __always_inline int eth_l3_off(struct __sk_buff *skb, __u32 *l3_off)
{
	__u16 eth_proto;
	__u32 off = sizeof(struct ethhdr);

	if (bpf_skb_load_bytes(skb, offsetof(struct ethhdr, h_proto), &eth_proto, sizeof(eth_proto)) < 0)
		return -1;

	/* One level of 802.1Q / 802.1ad is enough for typical media paths. */
	if (eth_proto == bpf_htons(ETH_P_8021Q) || eth_proto == bpf_htons(ETH_P_8021AD)) {
		if (bpf_skb_load_bytes(skb, off + 2, &eth_proto, sizeof(eth_proto)) < 0)
			return -1;
		off += 4;
	}

	if (eth_proto != bpf_htons(ETH_P_IP))
		return -1;

	*l3_off = off;
	return 0;
}

static __always_inline int parse_ipv4_udp(struct __sk_buff *skb, struct rtpengine_tc_key *key,
		__u32 *src_ip, __u16 *src_port, __u32 *l3_off, __u32 *l4_off, __u32 *udp_len,
		__u16 *udp_check)
{
	struct iphdr iph;
	struct udphdr udph;

	if (eth_l3_off(skb, l3_off) < 0)
		return -1;
	if (bpf_skb_load_bytes(skb, *l3_off, &iph, sizeof(iph)) < 0)
		return -1;
	if (iph.protocol != IPPROTO_UDP)
		return -1;
	if ((iph.ihl & 0x0f) < 5)
		return -1;

	*l4_off = *l3_off + (iph.ihl & 0x0f) * 4;
	if (bpf_skb_load_bytes(skb, *l4_off, &udph, sizeof(udph)) < 0)
		return -1;

	key->local.family = RTPENGINE_TC_AF_INET;
	key->local.port = udph.dest;
	key->local.pad = 0;
	key->local.u.ipv4 = iph.daddr;
	*src_ip = iph.saddr;
	*src_port = udph.source;
	*udp_len = bpf_ntohs(udph.len);
	*udp_check = udph.check;
	return 0;
}

static __always_inline int ipv4_replace(struct __sk_buff *skb, __u32 l3_off, __u32 l4_off,
		struct rtpengine_tc_flow *f, __u16 udp_check)
{
	__u32 old_saddr, old_daddr;
	__u16 old_sport, old_dport;
	__u32 new_saddr = f->src.u.ipv4;
	__u32 new_daddr = f->dst.u.ipv4;
	__u16 new_sport = f->src.port;
	__u16 new_dport = f->dst.port;

	if (bpf_skb_load_bytes(skb, l3_off + offsetof(struct iphdr, saddr), &old_saddr, 4) < 0)
		return -1;
	if (bpf_skb_load_bytes(skb, l3_off + offsetof(struct iphdr, daddr), &old_daddr, 4) < 0)
		return -1;
	if (bpf_skb_load_bytes(skb, l4_off + offsetof(struct udphdr, source), &old_sport, 2) < 0)
		return -1;
	if (bpf_skb_load_bytes(skb, l4_off + offsetof(struct udphdr, dest), &old_dport, 2) < 0)
		return -1;

	if (bpf_skb_store_bytes(skb, l3_off + offsetof(struct iphdr, saddr), &new_saddr, 4, 0) < 0)
		return -1;
	if (bpf_skb_store_bytes(skb, l3_off + offsetof(struct iphdr, daddr), &new_daddr, 4, 0) < 0)
		return -1;
	if (bpf_l3_csum_replace(skb, l3_off + offsetof(struct iphdr, check), old_saddr, new_saddr, 4) < 0)
		return -1;
	if (bpf_l3_csum_replace(skb, l3_off + offsetof(struct iphdr, check), old_daddr, new_daddr, 4) < 0)
		return -1;

	if (bpf_skb_store_bytes(skb, l4_off + offsetof(struct udphdr, source), &new_sport, 2, 0) < 0)
		return -1;
	if (bpf_skb_store_bytes(skb, l4_off + offsetof(struct udphdr, dest), &new_dport, 2, 0) < 0)
		return -1;

	/* IPv4 UDP checksum 0 means "not used" — do not invent a checksum. */
	if (udp_check) {
		if (bpf_l4_csum_replace(skb, l4_off + offsetof(struct udphdr, check), old_saddr, new_saddr,
				BPF_F_PSEUDO_HDR | 4) < 0)
			return -1;
		if (bpf_l4_csum_replace(skb, l4_off + offsetof(struct udphdr, check), old_daddr, new_daddr,
				BPF_F_PSEUDO_HDR | 4) < 0)
			return -1;
		if (bpf_l4_csum_replace(skb, l4_off + offsetof(struct udphdr, check), old_sport, new_sport, 2) < 0)
			return -1;
		if (bpf_l4_csum_replace(skb, l4_off + offsetof(struct udphdr, check), old_dport, new_dport, 2) < 0)
			return -1;
	}
	return 0;
}

SEC("tc")
int rtpengine_tc_ingress(struct __sk_buff *skb)
{
	struct rtpengine_tc_key key = {};
	struct rtpengine_tc_flow *flow;
	__u32 src_ip = 0;
	__u16 src_port = 0;
	__u32 l3_off = 0, l4_off = 0, udp_len = 0;
	__u16 udp_check = 0;
	int ret;

	if (parse_ipv4_udp(skb, &key, &src_ip, &src_port, &l3_off, &l4_off, &udp_len, &udp_check) < 0)
		return TC_ACT_OK;

	flow = bpf_map_lookup_elem(&flows, &key);
	if (!flow)
		return TC_ACT_OK;

	if (flow->flags & RTPENGINE_TC_F_CHECK_SRC) {
		if (flow->expected_src.family != RTPENGINE_TC_AF_INET)
			return TC_ACT_OK;
		if (flow->expected_src.u.ipv4 != src_ip || flow->expected_src.port != src_port)
			return TC_ACT_OK;
	}

	if (flow->src.family != RTPENGINE_TC_AF_INET || flow->dst.family != RTPENGINE_TC_AF_INET)
		return TC_ACT_OK;
	if (!flow->ifindex)
		return TC_ACT_OK;

	if (ipv4_replace(skb, l3_off, l4_off, flow, udp_check) < 0)
		return TC_ACT_OK;

	__sync_fetch_and_add(&flow->packets, 1);
	__sync_fetch_and_add(&flow->bytes, udp_len);

	/* Fill L2 from neighbour/FIB for the rewritten IPv4 destination. */
	ret = bpf_redirect_neigh(flow->ifindex, NULL, 0, 0);
	if (ret == TC_ACT_REDIRECT)
		return ret;
	/* Packet headers already rewritten — do not deliver to the socket. */
	return TC_ACT_SHOT;
}
