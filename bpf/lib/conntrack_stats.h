/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#pragma once

#include "common.h"

/*
 * CT packet/byte accounting, decoupled from the CT entry itself.
 *
 * These side maps contains only RX/TX counters and are per-CPU, so updates
 * are plain non-atomic increments. They are keyed by the exact same 5-tuple
 * as the CT maps themselves.
 *
 * CT_SERVICE lookups/creates (the pre-DNAT service-frontend hit, keyed on
 * the client/VIP tuple) are excluded: the packet always continues on to a
 * regular CT_EGRESS/CT_INGRESS lookup for the post-DNAT real flow, which
 * records the exact same packets under its own entry. Accounting both would
 * double-count every service-routed connection's tx bytes/packets while
 * adding a redundant map entry whose rx side is always zero.
 *
 * As for the CT maps, we might have the same 5tuple twice but with different
 * flags. This is the case when we observe both TUPLE_F_IN and TUPLE_F_OUT.
 * They are the exact same representation but with inverted order of counters.
 * We account for both of them. It is up to the userspace to correctly interpret
 * it and use only one of the two entries.
 */

struct ct_stats_value {
	__u64		rx_packets;
	__u64		rx_bytes;
	__u64		tx_packets;
	__u64		tx_bytes;
};

struct {
	__uint(type, BPF_MAP_TYPE_LRU_PERCPU_HASH);
	__type(key, struct ipv4_ct_tuple);
	__type(value, struct ct_stats_value);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(max_entries, CT_STATS_MAP_SIZE);
	__uint(map_flags, BPF_F_NO_COMMON_LRU);
} cilium_ct_stats4 __section_maps_btf;

struct {
	__uint(type, BPF_MAP_TYPE_LRU_PERCPU_HASH);
	__type(key, struct ipv6_ct_tuple);
	__type(value, struct ct_stats_value);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(max_entries, CT_STATS_MAP_SIZE);
	__uint(map_flags, BPF_F_NO_COMMON_LRU);
} cilium_ct_stats6 __section_maps_btf;

static __always_inline void *
get_ct_stats_map4(void)
{
	return &cilium_ct_stats4;
}

static __always_inline void *
get_ct_stats_map6(void)
{
	return &cilium_ct_stats6;
}

/* ct_stats_add adds one packet of the given size to value's rx or tx side
 * based on the direction.
 */
static __always_inline void
ct_stats_add(struct ct_stats_value *value, __u64 bytes, enum ct_dir dir)
{
	switch (dir) {
	case CT_INGRESS:
		value->rx_packets += 1;
		value->rx_bytes += bytes;
		break;
	case CT_EGRESS:
	case CT_SERVICE:
		value->tx_packets += 1;
		value->tx_bytes += bytes;
		break;
	}
}

/* ct_stats_create initializes the stats entry for a CT entry being created
 * right now. No-op for CT_SERVICE, see the file comment above.
 */
static __always_inline void
ct_stats_create(const void *map, const void *tuple, __u64 bytes, enum ct_dir dir)
{
	struct ct_stats_value newval = {};

	if (dir == CT_SERVICE)
		return;

	ct_stats_add(&newval, bytes, dir);
	map_update_elem(map, tuple, &newval, 0);
}

/* ct_stats_update accounts one packet for an existing (or lazily created)
 * CT entry. The stats map's LRU can evict independently of the CT map's own
 * entry lifecycle, so a missing entry is re-initialized.
 *
 * No-op for CT_SERVICE, see the file comment above.
 */
static __always_inline void
ct_stats_update(const void *map, const void *tuple, __u64 bytes, enum ct_dir dir)
{
	struct ct_stats_value *value;

	if (dir == CT_SERVICE)
		return;

	value = map_lookup_elem(map, tuple);
	if (value) {
		ct_stats_add(value, bytes, dir);
		return;
	}
	ct_stats_create(map, tuple, bytes, dir);
}
