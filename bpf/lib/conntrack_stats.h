/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#pragma once

#include "common.h"

/*
 * CT packet/byte per-direction accounting, decoupled from the CT entry itself.
 * The side maps hold only RX/TX counters, keyed by the same tuple as the CT maps.
 *
 * The same packets can be accounted by two entries: a TUPLE_F_SERVICE entry and
 * the CT_EGRESS/CT_INGRESS one of the post-DNAT flow, and a TUPLE_F_IN and a
 * TUPLE_F_OUT entry for pod-to-pod traffic within the same node, with RX and TX
 * swapped. It is up to the userspace to account only one of them.
 */

struct ct_stats {
	__u64		rx_packets;
	__u64		rx_bytes;
	__u64		tx_packets;
	__u64		tx_bytes;
};

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, struct ipv4_ct_tuple);
	__type(value, struct ct_stats);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(max_entries, CT_STATS_MAP_SIZE);
	__uint(map_flags, LRU_MEM_FLAVOR);
} cilium_ct_stats4 __section_maps_btf;

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, struct ipv6_ct_tuple);
	__type(value, struct ct_stats);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(max_entries, CT_STATS_MAP_SIZE);
	__uint(map_flags, LRU_MEM_FLAVOR);
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

static __always_inline void
ct_stats_add(struct ct_stats *value, __u64 bytes, enum ct_dir dir)
{
	if (dir == CT_INGRESS) {
		__sync_fetch_and_add(&value->rx_packets, 1);
		__sync_fetch_and_add(&value->rx_bytes, bytes);
	} else if (dir == CT_EGRESS || dir == CT_SERVICE) {
		__sync_fetch_and_add(&value->tx_packets, 1);
		__sync_fetch_and_add(&value->tx_bytes, bytes);
	}
}

static __always_inline int
ct_stats_create(const void *map, const void *tuple, __u64 bytes, enum ct_dir dir,
		unsigned int flags)
{
	struct ct_stats newval = {};

	ct_stats_add(&newval, bytes, dir);
	return map_update_elem(map, tuple, &newval, flags);
}

/* The stats map's LRU evicts independently of the CT map, so a missing entry is
 * re-created. BPF_NOEXIST avoids overwriting the entry another CPU just created.
 */
static __always_inline void
ct_stats_update(const void *map, const void *tuple, __u64 bytes, enum ct_dir dir)
{
	struct ct_stats *value;

	value = map_lookup_elem(map, tuple);
	if (!value) {
		if (ct_stats_create(map, tuple, bytes, dir, BPF_NOEXIST) == 0)
			return;
		value = map_lookup_elem(map, tuple);
	}
	if (value)
		ct_stats_add(value, bytes, dir);
}
