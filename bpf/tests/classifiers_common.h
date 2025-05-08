/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#define ENABLE_IPV4 1
#define ENABLE_IPV6 1
#define ENABLE_IPSEC 1
#define ENABLE_WIREGUARD 1

#if defined(IS_BPF_WIREGUARD)
# undef IS_BPF_WIREGUARD
# include "bpf_wireguard.c"
#elif defined(IS_BPF_HOST)
# undef IS_BPF_HOST
# include "bpf_host.c"
#else
# error "this file supports inclusion only from files with IS_BPF_HOST or IS_BPF_WIREGUARD defined"
#endif

#include "common.h"
#include "pktgen.h"

/* Remove the L2 layer to simulate packet in an L3 device. */
static __always_inline void
adjust_l2(struct __ctx_buff *ctx)
{
	if (!is_defined(IS_BPF_WIREGUARD))
		return;

	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	__u64 flags = BPF_F_ADJ_ROOM_FIXED_GSO;

	if ((void *)data + __ETH_HLEN + __ETH_HLEN <= data_end)
		memcpy(data, data + __ETH_HLEN, __ETH_HLEN);

	skb_adjust_room(ctx, -__ETH_HLEN, BPF_ADJ_ROOM_MAC, flags);
}

static __always_inline int
pktgen(struct __ctx_buff *ctx, bool is_ipv4)
{
	struct pktgen builder;
	struct udphdr *l4;

	pktgen__init(&builder, ctx);

	if (is_ipv4)
		l4 = pktgen__push_ipv4_udp_packet(&builder,
						  (__u8 *)mac_one,
						  (__u8 *)mac_two,
						  v4_node_one,
						  v4_node_two,
						  tcp_src_one,
						  tcp_src_two);
	else
		l4 = pktgen__push_ipv6_udp_packet(&builder,
						  (__u8 *)mac_one,
						  (__u8 *)mac_two,
						  (__u8 *)v6_node_one,
						  (__u8 *)v6_node_two,
						  tcp_src_one,
						  tcp_src_two);

	if (!l4)
		return TEST_ERROR;

	pktgen__finish(&builder);

	return 0;
}

PKTGEN("tc", "ctx_classify_by_eth_hlen")
static __always_inline int
ctx_classify_by_eth_hlen_pktgen(struct __ctx_buff *ctx) {
	return pktgen(ctx, true);
}

CHECK("tc", "ctx_classify_by_eth_hlen")
int ctx_classify_by_eth_hlen_check(struct __ctx_buff *ctx)
{
	test_init();

	adjust_l2(ctx);

	cls_flags_t flags = _ctx_classify_by_eth_hlen(ctx);
	cls_flags_t flags4 = _ctx_classify_by_eth_hlen4(ctx);
	cls_flags_t flags6 = _ctx_classify_by_eth_hlen6(ctx);

	assert(flags4 == flags);

	assert(flags6 & CLS_FLAG_IPV6);

	assert(flags6 == (flags | CLS_FLAG_IPV6));

	assert(((flags & CLS_FLAG_L3_DEV) != 0) == is_defined(IS_BPF_WIREGUARD));

	test_finish();
}

PKTGEN("tc", "ctx_classify4")
static __always_inline int
ctx_classify4_pktgen(struct __ctx_buff *ctx) {
	return pktgen(ctx, true);
}

CHECK("tc", "ctx_classify4")
int ctx_classify4_check(struct __ctx_buff *ctx)
{
	test_init();

	adjust_l2(ctx);

	void *data, *data_end;
	struct iphdr *ip4;
	struct udphdr *udp;
	cls_flags_t flags;

	assert(revalidate_data(ctx, &data, &data_end, &ip4));

	udp = (void *)ip4 + sizeof(struct iphdr);
	if ((void *)udp + sizeof(struct udphdr) > data_end)
		test_fatal("l4 out of bounds");

	flags = ctx_classify4(ctx, true);

	assert(!(flags & CLS_FLAG_WIREGUARD));

	udp->source = bpf_htons(WG_PORT);

	flags = ctx_classify4(ctx, true);

	assert(((flags & CLS_FLAG_WIREGUARD) != 0) == is_defined(IS_BPF_HOST));

	ctx->mark = MARK_MAGIC_ENCRYPT;

	flags = ctx_classify4(ctx, false);

	assert(((flags & CLS_FLAG_WIREGUARD) != 0) == is_defined(IS_BPF_HOST));

	ip4->protocol = IPPROTO_ESP;

	flags = ctx_classify4(ctx, true);

	assert(((flags & CLS_FLAG_IPSEC) != 0) == is_defined(IS_BPF_HOST));

	test_finish();
}

PKTGEN("tc", "ctx_classify6")
static __always_inline int
ctx_classify6_pktgen(struct __ctx_buff *ctx) {
	return pktgen(ctx, false);
}

CHECK("tc", "ctx_classify6")
int ctx_classify6_check(struct __ctx_buff *ctx)
{
	test_init();

	adjust_l2(ctx);

	void *data, *data_end;
	struct ipv6hdr *ip6;
	struct udphdr *udp;
	cls_flags_t flags;

	assert(revalidate_data(ctx, &data, &data_end, &ip6));

	udp = (void *)ip6 + sizeof(struct ipv6hdr);
	if ((void *)udp + sizeof(struct udphdr) > data_end)
		test_fatal("l4 out of bounds");

	flags = ctx_classify6(ctx, true);

	assert(!(flags & CLS_FLAG_WIREGUARD));

	udp->source = bpf_htons(WG_PORT);

	flags = ctx_classify6(ctx, true);

	assert(((flags & CLS_FLAG_WIREGUARD) != 0) == is_defined(IS_BPF_HOST));

	ctx->mark = MARK_MAGIC_ENCRYPT;

	flags = ctx_classify6(ctx, false);

	assert(((flags & CLS_FLAG_WIREGUARD) != 0) == is_defined(IS_BPF_HOST));

	ip6->nexthdr = IPPROTO_ESP;

	flags = ctx_classify6(ctx, true);

	assert(((flags & CLS_FLAG_IPSEC) != 0) == is_defined(IS_BPF_HOST));

	test_finish();
}
