/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#pragma once

#include "lib/common.h"
#include "lib/l4.h"
#include "lib/ipv4.h"
#include "lib/ipv6.h"

typedef __u8 cls_flags_t;

enum {
	CLS_FLAG_IPV6	   = (1 << 0),
	CLS_FLAG_L3_DEV    = (1 << 1),
	CLS_FLAG_DECRYPTED = (1 << 2),
	CLS_FLAG_WIREGUARD = (1 << 3),
	CLS_FLAG_IPSEC     = (1 << 4),
	CLS_FLAG_VXLAN     = (1 << 5),
	CLS_FLAG_GENEVE    = (1 << 6),
};

#define CLS_FLAG_NONE ((cls_flags_t)0)

/* Classifiers are used only for tracing TC packets in bpf_{host,wireguard}. */
#if __ctx_is == __ctx_skb
/* Compute classifiers for a potential L3 packet based on ETH_HLEN.
 * This is expected to be used right before emitting a trace/drop notification
 * in {trace,drop}.h, so that they can be correctly decoded from Monitor/Hubble.
 * - CLS_FLAG_L3_DEV: packet from a L3 device.
 * - CLS_FLAG_IPV6:   IPv6 packet, computed when also from a L3 device.
 *                    When already handling IPv6 packets, use _ctx_classify_by_eth_hlen6.
 * @ctx: the socket buffer
 */
static __always_inline cls_flags_t
_ctx_classify_by_eth_hlen(const struct __sk_buff *ctx)
{
	if (ETH_HLEN != 0)
		return CLS_FLAG_NONE;

	if (ctx->protocol == bpf_htons(ETH_P_IPV6))
		return CLS_FLAG_L3_DEV | CLS_FLAG_IPV6;

	return CLS_FLAG_L3_DEV;
}

static __always_inline cls_flags_t
_ctx_classify_by_eth_hlen4(const struct __sk_buff *ctx)
{
	if (!is_defined(ENABLE_IPV4))
		return CLS_FLAG_NONE;

	return _ctx_classify_by_eth_hlen(ctx);
}

static __always_inline cls_flags_t
_ctx_classify_by_eth_hlen6(const struct __sk_buff *ctx)
{
	if (!is_defined(ENABLE_IPV6))
		return CLS_FLAG_NONE;

	return _ctx_classify_by_eth_hlen(ctx) | CLS_FLAG_IPV6;
}

static __always_inline cls_flags_t
_ctx_classify_from_mark(struct __sk_buff *ctx)
{
	if (ctx_is_wireguard_encrypted(ctx))
		return CLS_FLAG_WIREGUARD;

	if (ctx_is_wireguard_decrypted(ctx))
		return CLS_FLAG_WIREGUARD | CLS_FLAG_DECRYPTED;

	if (ctx_is_overlay_encrypted(ctx) || ctx_is_ipsec_encrypted(ctx))
		return CLS_FLAG_IPSEC;

	if (ctx_is_ipsec_decrypted(ctx))
		return CLS_FLAG_IPSEC | CLS_FLAG_DECRYPTED;

	if (ctx_is_overlay(ctx))
		switch (TUNNEL_PROTOCOL) {
		case TUNNEL_PROTOCOL_VXLAN:
			return CLS_FLAG_VXLAN;
		case TUNNEL_PROTOCOL_GENEVE:
			return CLS_FLAG_GENEVE;
		default:
			__throw_build_bug();
		}

	return CLS_FLAG_NONE;
}

static __always_inline cls_flags_t
_ctx_classify_from_pkt_hdr(struct __sk_buff *ctx, int l4_off, __u8 l4_proto)
{
	struct {
		__be16 sport;
		__be16 dport;
	} l4;

	switch (l4_proto) {
	case IPPROTO_ESP:
		if (is_defined(ENABLE_IPSEC))
			return CLS_FLAG_IPSEC;

		break;
	case IPPROTO_UDP:
		if (l4_load_ports(ctx, l4_off + UDP_SPORT_OFF, &l4.sport) < 0)
			break;

		if (is_defined(ENABLE_WIREGUARD) &&
		    (l4.sport == bpf_htons(WG_PORT) || l4.dport == bpf_htons(WG_PORT)))
			return CLS_FLAG_WIREGUARD;

		if (is_defined(HAVE_ENCAP) &&
			(l4.sport == bpf_htons(TUNNEL_PORT) || l4.dport == bpf_htons(TUNNEL_PORT)))
			switch (TUNNEL_PROTOCOL) {
			case TUNNEL_PROTOCOL_VXLAN:
				return CLS_FLAG_VXLAN;
			case TUNNEL_PROTOCOL_GENEVE:
				return CLS_FLAG_GENEVE;
			default:
				__throw_build_bug();
			}

		break;
	}

	return CLS_FLAG_NONE;
}

static __always_inline cls_flags_t
ctx_classify6(struct __sk_buff *ctx, bool dpi)
{
	cls_flags_t flags = CLS_FLAG_NONE;
	void *data, *data_end;
	struct ipv6hdr *ip6;
	__u8 next_proto;
	int hdrlen;

	flags = _ctx_classify_from_mark(ctx);
	if (flags != CLS_FLAG_NONE)
		goto out;

	if (!dpi)
		goto out;

	if (!revalidate_data(ctx, &data, &data_end, &ip6))
		goto out;

	next_proto = ip6->nexthdr;
	hdrlen = ipv6_hdrlen(ctx, &next_proto);

	if (hdrlen < 0)
		goto out;

	flags = _ctx_classify_from_pkt_hdr(ctx, ETH_HLEN + hdrlen, next_proto);

out:
	return flags | CLS_FLAG_IPV6;
}

static __always_inline cls_flags_t
ctx_classify4(struct __sk_buff *ctx, bool dpi)
{
	cls_flags_t flags = CLS_FLAG_NONE;
	void *data, *data_end;
	struct iphdr *ip4;
	__u8 next_proto;
	int hdrlen;

	flags = _ctx_classify_from_mark(ctx);
	if (flags != CLS_FLAG_NONE)
		goto out;

	if (!dpi)
		goto out;

	if (!revalidate_data(ctx, &data, &data_end, &ip4))
		goto out;

	next_proto = ip4->protocol;
	hdrlen = ipv4_hdrlen(ip4);
	flags = _ctx_classify_from_pkt_hdr(ctx, ETH_HLEN + hdrlen, next_proto);

out:
	return flags;
}

static __always_inline cls_flags_t
ctx_classify(struct __sk_buff *ctx, bool dpi)
{
	cls_flags_t flags = CLS_FLAG_NONE;
	void *data, *data_end;
	struct ipv6hdr *ip6;
	struct iphdr *ip4;
	__be16 proto;
	__u8 next_proto;
	int hdrlen;

	flags = _ctx_classify_from_mark(ctx);
	if (flags != CLS_FLAG_NONE)
		goto out;

	if (!dpi)
		goto out;

	if (!validate_ethertype(ctx, &proto))
		goto out;

	switch (proto) {
	case bpf_htons(ETH_P_IPV6):
		flags = CLS_FLAG_IPV6;
		if (!is_defined(ENABLE_IPV6))
			goto out;

		if (!revalidate_data_pull(ctx, &data, &data_end, &ip6))
			goto out;

		next_proto = ip6->nexthdr;
		hdrlen = ipv6_hdrlen(ctx, &next_proto);

		if (hdrlen < 0)
			goto out;

		flags |= _ctx_classify_from_pkt_hdr(ctx, ETH_HLEN + hdrlen, next_proto);

		break;
	case bpf_htons(ETH_P_IP):
		if (!is_defined(ENABLE_IPV4))
			goto out;

		if (!revalidate_data_pull(ctx, &data, &data_end, &ip4))
			goto out;

		next_proto = ip4->protocol;
		hdrlen = ipv4_hdrlen(ip4);
		flags = _ctx_classify_from_pkt_hdr(ctx, ETH_HLEN + hdrlen, next_proto);

		break;
	}

out:
	return flags;
}

/* Compute payload length from the given classifiers:
 * - TRACE_PAYLOAD_LEN_OVERLAY, when CLS_FLAG_{VXLAN,GENEVE} is set
 * - TRACE_PAYLOAD_LEN, otherwise.
 */
static __always_inline __u64
_ctx_payloadlen_from_flags(cls_flags_t flags)
{
	if  (is_defined(HAVE_ENCAP) &&
		((flags & CLS_FLAG_VXLAN) || (flags & CLS_FLAG_GENEVE)))
		return CONFIG(trace_payload_len_overlay);

	return CONFIG(trace_payload_len);
}
#else
# define _ctx_payloadlen_from_flags(flags)    CONFIG(trace_payload_len)
# define _ctx_classify_by_eth_hlen(ctx)       CLS_FLAG_NONE
# define _ctx_classify_by_eth_hlen4(ctx)      CLS_FLAG_NONE
# define _ctx_classify_by_eth_hlen6(ctx)      CLS_FLAG_NONE
# define ctx_classify(ctx, proto)        CLS_FLAG_NONE
# define ctx_classify4(ctx, ip4)         CLS_FLAG_NONE
# define ctx_classify6(ctx, ip6)         CLS_FLAG_NONE
#endif
