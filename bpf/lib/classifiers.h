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
/* Compute classifiers for a potential L3 packet based on ETH_HLEN.
 * This is expected to be used right before emitting a trace/drop notification
 * in {trace,drop}.h, so that they can be correctly decoded from Monitor/Hubble.
 * - CLS_FLAG_L3_DEV: packet from a L3 device.
 * - CLS_FLAG_IPV6:   IPv6 packet, computed when also from a L3 device.
 *                    When already handling IPv6 packets, use _ctx_classify_by_eth_hlen6.
 * @ctx: the socket buffer
 */
static __always_inline cls_flags_t
_ctx_classify_by_eth_hlen(const struct __ctx_buff *ctx __maybe_unused)
{
	if (ETH_HLEN != 0)
		return CLS_FLAG_NONE;

	if (ctx_get_protocol(ctx) == bpf_htons(ETH_P_IPV6))
		return CLS_FLAG_L3_DEV | CLS_FLAG_IPV6;

	return CLS_FLAG_L3_DEV;
}

static __always_inline cls_flags_t
_ctx_classify_from_pkt_hdr(struct __ctx_buff *ctx __maybe_unused, int l4_off __maybe_unused, __u8 l4_proto __maybe_unused, bool emit __maybe_unused)
{
	struct {
		__be16 sport;
		__be16 dport;
	} l4 __maybe_unused;

	switch (l4_proto) {
#if defined(ENABLE_IPSEC) && (defined(IS_BPF_XDP) || defined(IS_BPF_HOST))
	case IPPROTO_ESP:
		return CLS_FLAG_IPSEC;
#endif
#if (defined(ENABLE_WIREGUARD) && (defined(IS_BPF_XDP) || defined(IS_BPF_HOST))) || \
	(defined(HAVE_ENCAP) && (defined(IS_BPF_XDP) || defined(IS_BPF_HOST) || defined(IS_BPF_WIREGUARD)))
	case IPPROTO_UDP:
		if (l4_load_ports(ctx, l4_off + UDP_SPORT_OFF, &l4.sport) < 0)
			break;

#if (defined(ENABLE_WIREGUARD) && (defined(IS_BPF_XDP) || defined(IS_BPF_HOST)))
		if (l4.sport == bpf_htons(WG_PORT) || l4.dport == bpf_htons(WG_PORT))
			return CLS_FLAG_WIREGUARD;
#endif

#if (defined(HAVE_ENCAP) && (defined(IS_BPF_XDP) || defined(IS_BPF_HOST) || defined(IS_BPF_WIREGUARD)))
		if (emit && (l4.sport == bpf_htons(TUNNEL_PORT) || l4.dport == bpf_htons(TUNNEL_PORT)))
			switch (TUNNEL_PROTOCOL) {
			case TUNNEL_PROTOCOL_VXLAN:
				return CLS_FLAG_VXLAN;
			case TUNNEL_PROTOCOL_GENEVE:
				return CLS_FLAG_GENEVE;
			default:
				__throw_build_bug();
			}
#endif

		break;
#endif
	}

	return CLS_FLAG_NONE;
}

static __always_inline cls_flags_t
ctx_classify(struct __ctx_buff *ctx __maybe_unused, bool emit __maybe_unused)
{
	cls_flags_t flags = CLS_FLAG_NONE;
	void *data, *data_end __maybe_unused;
	struct ipv6hdr *ip6 __maybe_unused;
	struct iphdr *ip4 __maybe_unused;
	__u8 next_proto __maybe_unused;
	int hdrlen __maybe_unused;
	__be16 proto;

	if (emit)
		flags |= _ctx_classify_by_eth_hlen(ctx);

#ifndef IS_BPF_XDP
	if (is_defined(IS_BPF_HOST) && ctx_is_wireguard_encrypted(ctx)) {
		flags |= CLS_FLAG_WIREGUARD;
		goto out;
	}

	if (is_defined(IS_BPF_HOST) && (ctx_is_ipsec_decrypted(ctx) || ctx_is_overlay_encrypted(ctx))) {
		flags |= CLS_FLAG_IPSEC;
		goto out;
	}

	if (ctx_is_wireguard_decrypted(ctx)) {
		flags |= CLS_FLAG_WIREGUARD | CLS_FLAG_DECRYPTED;
		goto overlay;
	}

	if (ctx_is_ipsec_encrypted(ctx)) {
		flags |= CLS_FLAG_IPSEC | CLS_FLAG_DECRYPTED;
		goto overlay;
	}

overlay:
	if ((is_defined(IS_BPF_HOST) || is_defined(IS_BPF_WIREGUARD)) && ctx_is_overlay(ctx)) {
		switch (TUNNEL_PROTOCOL) {
		case TUNNEL_PROTOCOL_VXLAN:
			flags |= CLS_FLAG_VXLAN;
			break;
		case TUNNEL_PROTOCOL_GENEVE:
			flags |= CLS_FLAG_GENEVE;
			break;
		default:
			__throw_build_bug();
		}

		goto out;
	}
#endif

	if (!emit && !is_defined(ENABLE_IPSEC) && !is_defined(IS_BPF_WIREGUARD))
		goto out;

	proto = ctx_get_protocol(ctx);

	switch (proto) {
#ifdef ENABLE_IPV6
	case bpf_htons(ETH_P_IPV6):
		if (!revalidate_data(ctx, &data, &data_end, &ip6))
			goto out;

		next_proto = ip6->nexthdr;
		hdrlen = sizeof(struct ipv6hdr);

		flags |= _ctx_classify_from_pkt_hdr(ctx, ETH_HLEN + hdrlen, next_proto, emit);

		break;
#endif
#ifdef ENABLE_IPV4
	case bpf_htons(ETH_P_IP):
		if (!revalidate_data(ctx, &data, &data_end, &ip4))
			goto out;

		next_proto = ip4->protocol;
		hdrlen = ipv4_hdrlen(ip4);
		flags |= _ctx_classify_from_pkt_hdr(ctx, ETH_HLEN + hdrlen, next_proto, emit);

		break;
#endif
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
	if  (is_defined(HAVE_ENCAP) && (!is_defined(IS_BPF_LXC) && !is_defined(IS_BPF_OVERLAY) && !is_defined(IS_BPF_SOCK)) &&
		((TUNNEL_PROTOCOL == TUNNEL_PROTOCOL_VXLAN && flags & CLS_FLAG_VXLAN) || (TUNNEL_PROTOCOL == TUNNEL_PROTOCOL_GENEVE && flags & CLS_FLAG_GENEVE)))
		return CONFIG(trace_payload_len_overlay);

	return CONFIG(trace_payload_len);
}
