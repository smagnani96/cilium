/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#pragma once

#include "lib/common.h"

typedef __u8 cls_flags_t;

enum {
	CLS_FLAG_IPV6	   = (1 << 0),
	CLS_FLAG_L3_DEV    = (1 << 1),
};

#define CLS_FLAG_NONE ((cls_flags_t)0)

/* Classifiers are used only for tracing TC packets in bpf_{host,wireguard}. */
#if defined(IS_BPF_WIREGUARD) || defined(IS_BPF_HOST)
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
#else
# define _ctx_classify_by_eth_hlen(ctx)       CLS_FLAG_NONE
# define _ctx_classify_by_eth_hlen4(ctx)      CLS_FLAG_NONE
# define _ctx_classify_by_eth_hlen6(ctx)      CLS_FLAG_NONE
#endif
