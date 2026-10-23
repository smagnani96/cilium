# CFP-XXXX: Exposing per-direction traffic stats counters from datapath conntrack

**SIG: SIG-Datapath, SIG-Hubble**

**Begin Design Discussion:** XXXX

**Cilium Release:** 1.21

**Authors:** Simone Magnani <simone.magnani@isovalent.com>, Alexandre Perrin <alex@isovalent.com>

**Status:** Draft

## Summary

Cilium's connection tracking (CT) map knows that a connection exists, but not
how much traffic it carried. This CFP proposes an opt-in BPF side map holding
packet and byte counters per direction for each tracked connection, and three
ways to read it: Prometheus metrics, a new `GetConntrackStats` Hubble RPC
(served by the agent and merged cluster-wide by Hubble Relay), and the
`hubble list conntrack` and `cilium-dbg bpf ct stats` commands.

This CFP focuses on the decisions I would like to settle before merging the
current PoC, listed in [Open questions](#open-questions). Two of them shape the
scope the most: (a) the datapath implementation (cpu vs memory trade-off),
and (b) Hubble Relay, where a cluster-wide query holds the tables of every node
in memory and can consume a lot of it (see [Hubble Relay](#hubble-relay)).

## Motivation

### The gap

Up until v1.15 the CT entry held packet and byte counters, but they were removed
to make space for other fields (e.g. DSR). Today there is no free space left in
the CT entry, and growing the struct would break live connections on the first
upgrade or downgrade, as the BPF map would be recreated. `bpf-conntrack-accounting`
still exists behind a flag, but it only keeps a single packet counter and a
single byte counter in `struct ct_entry`, with no split by direction and no API
on top. This CFP does not deprecate it. As things stand, answering "how many
bytes did this connection move?" is not really possible:

* Hubble flows are events. They can be dropped by the ring buffer or the rate
  limiter, and they carry no byte counts, so a total can only be rebuilt by
  summing events and hoping nothing was lost.
* Hubble and Prometheus flow metrics are aggregated by label. They tell us that
  traffic exists between two workloads, not which connections produced it.
* `cilium-dbg bpf ct list` shows tuples and lifetimes, one node at a time.

### Why now: limits enforced per flow

The strongest need I have seen comes from running on public clouds. Providers enforce limits on the
network traffic of a VM: how many flows it can hold, how many packets per second
it can send, in some cases a rate per flow that differs by direction, a rate of
new connections (e.g. SYNs per second), and sometimes a limit scoped to a single
externally-exposed IP (e.g. a load balancer VIP) rather than to the whole node.
When one of them is hit, packets are silently dropped from the point of view of
the cluster, and the symptom looks like application latency or random
connection resets.

To stay below those limits, an operator needs four things that Cilium does not
give today:

1. Packets and bytes per connection and per direction. Whether the budget is
   spent by many small flows or by a few heavy ones changes what to do about it.
2. A cheap, periodic read. The consumer is a monitoring system scraping every
   few minutes and deriving rates from the difference between two scrapes. It
   does not need events, it needs cumulative counters available when asked.
3. No extra component. Many clusters will not deploy yet another daemon just to
   read flow counters, nor enable a feature costing noticeable CPU on every
   packet. It has to be part of Cilium, disabled by default, with a small and
   predictable overhead.
4. A way to bound what gets paid for. Many of these limits apply to traffic
   leaving the node towards other nodes or the outside world, not to
   intra-node pod traffic, so accounting only matters for a subset of
   connections. The first release accounts every tracked connection and lets
   the API/CLI filter at read time; see [Future work](#future-work) for
   narrowing this at the datapath level too.

The same data also answers what administrators already ask us: who are the top
talkers, who is the noisy neighbour on a node, which services a workload really
calls, and whether a policy matches the traffic that actually flows. For shared
clusters, it gives the volume per namespace or per exposed NodePort/LoadBalancer
service, useful for capacity planning.

### What it is not

It is not a billing system, see [Consistency](#consistency-with-the-ct-map) for
why. It cannot catch a burst either: cumulative counters read every few minutes
only show averages, so they tell how close a node is running to a limit, not
whether a spike crossed it. And it does not replace flows, which describe what
happened to individual packets.

## Goals

* Cumulative packets and bytes per direction for each tracked connection, plus
  the totals of the connections already garbage collected, as metrics.
* No changes to `struct ct_entry` nor the CT maps, to avoid recreating them and
  disrupting live connections on upgrade or downgrade.
* Opt-in, with no datapath or API cost when disabled.
* A memory footprint the operator can bound.
* One API for a single node and for a whole cluster, where callers pay only for
  what they ask for (name resolution, filtering, aggregation).

## Non-Goals

* Per-packet or per-flow visibility.
* Storing history or computing rates. Counters are cumulative and it is up to
  the consumer to derive rates.
* Exact accounting under map pressure.
* L7 accounting, TCP state, RTT or retransmissions.
* Tenant isolation in the API (see [Security](#security-and-access)).

## Proposal

```
                datapath                                     agent                     relay                   client
CT lookup/create  --->  cilium_ct_stats{4,6}  --->  pkg/ctstats cache
                                                     |--> Prometheus metrics
                                                     '--> GetConntrackStats  --->  merge + cache  --->  hubble list conntrack
```

### Datapath

`cilium_ct_stats4` and `cilium_ct_stats6` are LRU hash maps with the same key as
the CT maps, and four `u64` as value: rx and tx packets and bytes. They are
created only when `--bpf-ct-stats` is set (Helm `bpf.ctStats.enabled`),
which also sets the `enable_conntrack_stats` node config for the datapath. Like
the other Cilium maps they are pinned to bpffs, thus they survive an agent
restart.

On every CT lookup the datapath updates the stats entry with atomic adds. When a
connection is created, its stats entry is created too, and removed again if the
CT insert fails. If the stats entry is missing on a lookup (it was evicted, or
the feature was enabled after the connection), it is created with `BPF_NOEXIST`
so that two CPUs missing at the same time do not overwrite each other's packets.
The garbage collection (GC) of expired CT entries removes the stats entry along
with the CT entry, and adds its counters to
`cilium_datapath_conntrack_stats_gc_{packets,bytes}_total`.

What gets counted is whatever goes through the CT lookup, with the length
coming from `ctx_full_len()`, same as `bpf-conntrack-accounting`. This implies
that packets dropped after the lookup are still counted, and that whether the L2
header is part of the length depends on the hook. Both need to be spelled out in
the user documentation.

Two kinds of entries need care when reading the map:

* `TUPLE_F_IN` and `TUPLE_F_OUT`: pod-to-pod traffic on the same node is seen
  once per direction, producing two entries with the same 5-tuple and mirrored
  counters. The datapath counts both, and userspace keeps one.
* `TUPLE_F_SERVICE`: the entry for the client-to-VIP leg of a service
  connection, before DNAT. See [Service entries](#service-entries).

### How the counters are kept

I've evaluated four schemes, all of them as BPF programs run on a test machine
(numbers in the [appendix](#appendix-benchmarks)):

* `percpu`: per-CPU LRU hash keyed by the tuple. No contention, but memory grows
  with the number of CPUs. This was also my first idea.
* `cpukey`: plain LRU keyed by tuple and CPU id.
* `atomic`: plain LRU keyed by tuple, updated atomically.
* `atomicdir`: same as `atomic`, but keyed by tuple and direction.

I was expecting `percpu` to win, and it does on the hit path, but only by a
little: 25-39 ns against 46-70 ns for `atomic`, with a baseline of 10-19 ns
w/o any counter update. The exception is one flow hit by several cores, where
`atomic` takes 133 ns against 27 ns on 4 CPUs because the cache line bounces.
However, once the map is full and entries get evicted, `percpu` is the slowest
(850 ns against ~600 ns with the common LRU on 4 CPUs), as every insert has to
allocate and zero a value for each CPU. With the common LRU its lock dominates
anyway, and with `NO_COMMON_LRU` all of them are 2-5x faster. `cpukey`
tracks `atomic` under eviction, but it needs a GC that understands the CPU part
of the key, and its number of entries grows with the number of CPUs.

I opted for `atomic`: it is the smallest, it doesn't require any change in the
GC, and the case where it behaves worst (a single very hot flow touched by many
cores) is not the usual one on a node. If you have that workload, I'd like to
hear about it. What I don't have yet is an end-to-end number, see the first of
the [Open questions](#open-questions). The feature has to integrate with the
whole Cilium datapath, so it makes little sense to over-optimize it on day 0 if
the bottleneck is somewhere else in the datapath we're always paying for. Letting
users choose another scheme is covered in [Future work](#future-work).

### Userspace cache

`pkg/ctstats` turns a walk of the stats maps into an immutable snapshot and
refreshes it at most once per TTL (`bpf.ctStats.cacheTTL`, 30s by default), no
matter how many callers ask concurrently, and failures are not cached. The
connections removed by the GC since the last refresh are remembered up to a cap
(half of the map size, at least 65536), so that the next snapshot can report them
as not alive. Beyond the cap they disappear from the API, but they are still
part of the GC metrics. Metrics, `cilium-dbg` and Hubble all read from this
cache, so a burst of scrapes doesn't turn into a burst of map walks.

### Metrics

Labels are `family`, `protocol`, `status` and `direction`. Nothing is labelled
per connection, so the cardinality does not grow with the traffic.

* `cilium_datapath_conntrack_stats_{packets,bytes,entries}`: alive connections,
  computed at scrape time from the cache. Mirrored and service entries are
  counted once.
* `cilium_datapath_conntrack_stats_gc_{packets,bytes}_total`: connections
  retired by the GC.

For the cloud limits case, metrics give the totals of a node, and the API below
gives the per-connection view that explains them.

### Hubble API

```proto
rpc GetConntrackStats(conntrack.GetStatsRequest) returns (stream conntrack.GetStatsResponse);
```

`GetStatsRequest` takes `resolve`, a `filter` and a `group_by`. The response
stream carries `Entry` messages (tuple and flags, rx and tx packets and bytes,
whether it is alive, and `count` when aggregated), `IndexedEndpoint`,
`IndexedService` and `IndexedNode` messages, and in Relay a `node_status` for
each node failing to answer. The full definition is in
`api/v1/conntrack/conntrack.proto`.

Endpoints, services and nodes are not repeated in each entry: they are sent once,
before the entries referencing them, and entries only carry a `uint32` index.
With a million connections between a few hundred pods, this is the difference
between sending a few hundred names and a million. It's not the usual Hubble
shape and I'm open to alternatives, but inline names make the response several
times bigger.

Resolution is opt-in, as in the flow API, because each address costs a lookup.
It relies on the shared Hubble resolver and runs once per cache refresh instead
of per request. Endpoints are resolved for every address, services only for
service entries (the only place a VIP shows up), and nodes only for the
addresses that are not pods.

Filters match IPs and CIDRs, ports, protocols, endpoints (`[ns/]pod-prefix`),
the destination service and nodes. A filter on a resolved field without
`resolve`, or a malformed IP or CIDR, is rejected with `InvalidArgument` before
fetching any data. `group_by` accepts the same fields, sums the counters and
reports the size of the group in `count`. Both run on the cached snapshot, which
is never modified.

### Hubble Relay

Relay asks every agent, rewrites the per-node indices into cluster-wide ones and
merges the repeated entries. A node failing to answer becomes a `node_status`
instead of failing the whole call. The merged snapshot is cached
(`hubble.relay.ctStatsCacheTTL`, 30s by default), separately for `resolve` on and
off.

Relay forwards `resolve` to the agents, but not the filter nor `group_by`.
Pushing them down would make every distinct query skip the cache, and the
aggregation across nodes would need a second merge. The tradeoff is that Relay
always holds the full tables of all the nodes, and that doesn't scale: 100k
connections per node over 1000 nodes are 100M entries, which don't fit in Relay.
Therefore, I think the first release needs a limit. I propose a configurable
maximum number of entries in the merged snapshot (e.g. 1M, a few hundred MB),
above which the call fails with a message pointing to a node-level query. Pushing
selective filters down to the agents is the natural next step. Another option is to
make Relay stream each node's response to the consumer as is, without merging.

### CLI

`hubble list conntrack` takes `--resolve`, a flag for each filter of the API
(`--source-ip`, `--destination-service`, `--destination-node`, ...) and
`--group-by`, with table or JSON output. For instance, the heaviest destinations
of a namespace:

```bash
hubble list conntrack --resolve --source-endpoint my-namespace/ \
    --group-by destination-service --output json
```

```bash
$ ./hubble list conntrack --resolve
SOURCE                                                                            DESTINATION                                                                                             PROTO    ALIVE   RX PACKETS   TX PACKETS   RX BYTES   TX BYTES
10.244.0.105:36484 (reserved:host, node:kind-control-plane)                       10.244.0.227:8181 (kube-system/coredns-589f44dc88-v4rgg)                                                TCP      true    5            5            447        475
10.244.0.105:59898 (reserved:host, node:kind-control-plane)                       10.244.0.227:8181 (kube-system/coredns-589f44dc88-v4rgg)                                                TCP      false   6            5            513        475
10.244.0.105:40888 (reserved:host, node:kind-control-plane)                       10.244.0.247:8181 (cilium-test-1/echo-other-node-5769bd665b-v4dlr)                                      TCP      true    6            5            513        475
10.244.0.105:59802 (reserved:host, node:kind-control-plane)                       10.244.0.247:8181 (cilium-test-1/echo-other-node-5769bd665b-v4dlr)                                      TCP      true    5            5            447        475
10.244.0.110:50172 (local-path-storage/local-path-provisioner-855c7b7774-97vvf)   172.18.0.2:6443 (reserved:host, svc:default/kubernetes, node:kind-control-plane)                        TCP      true    5            7            770        540
10.244.0.160:42986 (kube-system/coredns-589f44dc88-c2qz7)                         172.18.0.2:6443 (reserved:host, svc:default/kubernetes, node:kind-control-plane)                        TCP      true    9            10           1364       738
10.244.0.227:51964 (kube-system/coredns-589f44dc88-v4rgg)                         172.18.0.2:6443 (reserved:host, svc:default/kubernetes, node:kind-control-plane)                        TCP      true    9            10           1364       738
10.244.0.237:4240 (reserved:health, node:kind-control-plane)                      10.244.0.105:58546 (reserved:host, node:kind-control-plane)                                             TCP      true    10           8            866        678
10.244.1.200:48350 (cilium-test-1/client-657b75749d-9kkdx)                        10.244.0.247:8080 (cilium-test-1/echo-other-node-5769bd665b-v4dlr, svc:cilium-test-1/echo-other-node)   TCP      true    4            6            2718       487
10.244.1.200:48360 (cilium-test-1/client-657b75749d-9kkdx)                        10.244.0.247:8080 (cilium-test-1/echo-other-node-5769bd665b-v4dlr, svc:cilium-test-1/echo-other-node)   TCP      true    4            6            2718       487
10.244.1.200:52932 (cilium-test-1/client-657b75749d-9kkdx)                        10.244.1.212:8080 (cilium-test-1/echo-same-node-7d8968df78-rdp2g, svc:cilium-test-1/echo-same-node)     TCP      true    4            6            2718       486
10.244.1.200:52916 (cilium-test-1/client-657b75749d-9kkdx)                        10.244.1.212:8080 (cilium-test-1/echo-same-node-7d8968df78-rdp2g, svc:cilium-test-1/echo-same-node)     TCP      true    4            6            2718       486
10.244.1.217:44012 (reserved:remote-node, node:kind-worker)                       10.244.0.237:4240 (reserved:health, node:kind-control-plane)                                            TCP      true    2            1            132        66
10.244.1.217:58670 (reserved:host, node:kind-worker)                              10.244.1.13:8181 (cilium-test-1/l7-lb-7ddb9855ff-4rtxj)                                                 TCP      true    6            5            512        475
10.244.1.217:52054 (reserved:host, node:kind-worker)                              10.244.1.212:8181 (cilium-test-1/echo-same-node-7d8968df78-rdp2g)                                       TCP      true    6            5            513        475
10.244.1.217:52616 (reserved:host, node:kind-worker)                              10.244.1.219:4222 (kube-system/hubble-relay-847cbc8fc5-8t978)                                           TCP      true    12           9            1067       745
172.18.0.2:4244 (reserved:kube-apiserver, node:kind-control-plane)                10.244.1.219:41044 (kube-system/hubble-relay-847cbc8fc5-8t978)                                          TCP      true    13           15           4981       1286
10.244.1.200:37284 (cilium-test-1/client-657b75749d-9kkdx)                        10.244.0.160:53 (kube-system/coredns-589f44dc88-c2qz7, svc:kube-system/kube-dns)                        UDP      true    2            2            370        234
10.244.1.200:36553 (cilium-test-1/client-657b75749d-9kkdx)                        10.244.0.227:53 (kube-system/coredns-589f44dc88-v4rgg, svc:kube-system/kube-dns)                        UDP      true    2            2            370        234
10.244.1.200:53552 (cilium-test-1/client-657b75749d-9kkdx)                        10.244.0.227:53 (kube-system/coredns-589f44dc88-v4rgg, svc:kube-system/kube-dns)                        UDP      true    2            2            370        234
fd00:10:244::6ad0:18545 (reserved:host, node:kind-control-plane)                  fd00:10:244::52e:0 (reserved:health, node:kind-control-plane)                                           ICMPv6   true    1            1            86         86
fd00:10:244::6ad0:59146 (reserved:remote-node, node:kind-control-plane)           fd00:10:244:1::65b0:0 (reserved:health, node:kind-worker)                                               ICMPv6   true    1            1            86         86
fd00:10:244:1::1db4:4917 (reserved:remote-node, node:kind-worker)                 fd00:10:244::52e:0 (reserved:health, node:kind-control-plane)                                           ICMPv6   true    1            1            86         86
```

`cilium-dbg bpf ct stats list` dumps the raw maps of a node, and
`cilium-dbg bpf ct stats flush` resets them (debug only). This is destructive,
all flushed stats will not be reported by the Cilium agent.
`cilium-dbg bpf ct flush` will also GC related stats from these side maps. This
is also destructive, and the agent will not report those stats.

### Configuration

| Setting | Default | Meaning |
|---|---|---|
| `--bpf-ct-stats` / `bpf.ctStats.enabled` | off | maps, metrics and API data |
| `--bpf-ct-stats-map-max` / `bpf.ctStats.mapMax` | CT TCP + CT any size (786432 entries) | entries per stats map |
| `--bpf-ct-stats-cache-ttl` / `bpf.ctStats.cacheTTL` | 30s | agent snapshot lifetime |
| `hubble.relay.ctStatsCacheTTL` | 30s | Relay snapshot lifetime |

## Alternatives considered

**Growing or reshaping `struct ct_entry`.** Changing the size of the value makes
the agent recreate the CT map at the next restart, breaking live connections on
every upgrade and downgrade. Shrinking the counters to `u32` avoids that, but
needs userspace to follow wrap-arounds across restarts, and anyone reading the raw
map still sees the overflowed values. A side map has none of these problems,
leaves room in the CT entry for other data (e.g. a policy cookie), and allows
changing its layout later without touching the CT maps.

**Reusing `bpf-conntrack-accounting` with a reader at dump time.** The cheapest
option, as there is no second map. However, it is tied to the CT entry layout, so
it can't evolve without hitting the problem above, and it has no split by
direction. The two can coexist, and be converged later.

**A per-CPU map.** This is the `percpu` scheme above: it wins on the hit path and
loses under eviction and on memory. It remains an option, see
[Future work](#future-work).

**Counting somewhere else.** Polling the CT map from userspace can't see bytes.
Reading the kernel's own per-socket counters, as Tetragon does, is free for TCP:
`tcp_info` already tracks packets and bytes per connection, so there is nothing
to add on the packet path. But it only sees traffic that terminates in a local
socket on that node, so traffic the node only forwards or load-balances (e.g.
NodePort/LB traffic on a node that isn't running the backend, or DSR) has no
socket there and is invisible, and UDP and ICMP have no equivalent per-flow
counter at all, which is why Tetragon falls back to the same kind of atomic
counter proposed here for those. Combining the two would mean two code paths
and two sources of truth for one feature; a single CT-side mechanism covers
every protocol and traffic shape with one scheme. Deriving the totals from
flows is lossy and costs more CPU and ring buffer than incrementing a counter.
Sampling one packet every N, or counting at connection close only, reduces the
cost but misses the long-lived connections until they end, which are the ones
the limits case needs to see. Events on close would need reliable delivery and a
consumer on every node. An aggregate per identity or endpoint would bound the
memory without a per-tuple map, but loses the connection view, so I see it more
as a possible complement.

## Design details

### Memory

Each entry stores the tuple plus 32 bytes: 14 + 32 for IPv4 and 38 + 32 for IPv6,
hash map overhead excluded. At the default size (CT TCP plus CT any, 786432
entries per family) that is about 36 MB for IPv4 and 55 MB for IPv6, and the LRU
bookkeeping can add up to as much again (estimation).

### Datapath cost

A packet on a tracked connection pays one more hash lookup and two atomic adds.
The microbenchmarks give 25-135 ns depending on contention, against a baseline of
10-19 ns, but for tiny working sets: a stats map of tens of MB adds cache
pressure that they don't capture. This is the reason for the opt-in, and for the
end-to-end measurement in the open questions. The verifier complexity of the CT
code on older kernels also needs a CI result.

### Consistency with the CT map

The stats map and the CT map are separate LRUs, and they evict independently. A
stats entry can be evicted while its connection is alive, restarting from zero at
the next packet, or it can outlive its CT entry until the next GC pass. The GC
metrics only cover what the GC removes, not what the LRU evicts.

There is a third case. When a client reuses the tuple of a connection that is
already closing, the datapath creates a new CT entry in its place and the stats
entry restarts with it. That is correct for a new connection, but the totals of
the old one never reach the GC metrics, and a consumer diffing two scrapes sees a
counter going backwards. Any rate computed from the difference has to treat a
decrease as a restart.

So the counters are right as long as the stats map fits the working set, and
become lower bounds when it doesn't. This assumes that a packet is counted only
once: whether it can be counted twice when crossing more than one hook is still
to be verified (see [Open questions](#open-questions), question 8), and until
then the counters should not be trusted as exact in either direction. That's fine to find the top talkers or to
track how close a node is to a limit, but not to bill to the byte. The pressure
is visible in the existing BPF map metrics, and I propose to add an eviction
counter to make the loss explicit, and a flag in the API for the entries that
were recreated.

### Service entries

A connection going through a service creates a service entry (client to VIP,
before DNAT, counted as tx only) and a regular entry keyed by the backend after
DNAT. Both count the same packets. This costs up to twice the entries
and updates for service traffic, and a total summing both counts the traffic
twice. The metrics skip the service entries, aggregations keep them apart from
the regular ones, and the CLI folds a service entry into its regular one.

I kept them because they are the only place where the VIP, thus the service, is
visible. With socket-LB the translation happens at `connect()` time, no service
entry exists, and the most common east-west case gets no service at all.

My preferred end state is to also scan the regular CT maps from userspace, to
retrieve other data (TCP flags, etc.). That includes the `rev_nat_index`, which
we could use to resolve the service and ignore `TUPLE_F_SERVICE`.

### Stale resolution

Names are resolved when the cache refreshes. A dead connection may be unresolved,
or resolve to a different endpoint that reused its IP. Node addresses scoped to
another cluster don't resolve yet, as the node lookup uses cluster ID 0.

## Operations

### Security and access

The Hubble API tells who talks to whom, which flows already do, and it goes through
the same Hubble server and TLS. `hubble.redact` only covers L7 data (HTTP URLs and
headers, Kafka) which the Hubble API never carries, so there is nothing to honour.

What the Hubble API adds is the ability to dump every connection of the cluster in a
single call. Hubble has no per-namespace or per-tenant scoping today and this CFP
doesn't add any: access to the Hubble API means access to all of it. The feature
is thus aimed at the cluster operator, not at tenants. The size limit in Relay
also bounds the cost of an expensive query. `cilium-dbg bpf ct stats flush` is
destructive, but it is only reachable by whoever has access to the node, like the
other `cilium-dbg bpf` commands.

### Upgrade, downgrade and toggling

Disabled by default, and no existing map changes. Enabling it adds the two pinned
maps and the node config flag, and stats start from zero for the connections
already tracked. A Hubble client that doesn't know the RPC gets `Unimplemented`.

### Rollout

A plain opt-in flag, with the Hubble API marked as beta in the first release,
since aggregation is the part I expect to change the most. If the end-to-end
numbers turn out to be bad, the fallback is to keep maps and metrics, and ship
another counting scheme (see [Future work](#future-work)) behind the same flag, as
the API doesn't depend on the counting scheme.

### Testing

BPF unit tests cover the accounting per direction and per tuple type. In
userspace, the cache, the exporter, the query, the Relay merge and the CLI have
unit tests. I'd add an end-to-end test sending a known amount of traffic between
pods with iperf, and comparing it with the reported bytes.

## Open questions

Questions 1 to 4 should be answered before accepting the CFP, the others can be
settled during the implementation review.

1. **End-to-end cost.** Throughput, CPU and latency with iperf on a real node,
   with and without the feature, with realistic flow counts and churn, plus the
   verifier complexity. I still have to produce these.
2. **Default map size.** It mirrors the CT maps so that every connection can have
   its stats. A smaller default would save memory, but counters would reset
   under pressure, which I believe is the worse failure. I'd keep it and document
   how to size it. Is that right?
3. **Service entries.** Do we stop accounting them already in the first release,
   or keep them and change this later? Dropping them early is cheaper than a
   visible change after the release.
4. **Relay limit.** Is a maximum snapshot size acceptable, or do we want either
   (a) filters pushed down to the agents from the start, or (b) Relay simply
   forwarding queries and replies?
5. **API placement.** `Observer` with a new `conntrack` package, or a separate
   service? Mixed versions during a rolling upgrade (a Relay talking to agents
   w/o the RPC) also need to be tested.
6. **Disabling.** Whether the pinned maps are removed when the feature is turned
   off again, and if not, whether they should be.
7. **Recreated entries.** Is a flag plus an eviction counter enough to make the
   loss under pressure visible, or should the API report it per entry?
8. **Double counting across hooks.** `ct_lookup` runs at several hooks. We need to
   verify that a packet crossing two of them (e.g. from-container then to-host
   on a local path) doesn't update the same stats entry twice.

9. **Accounting scope.** Should operators be able to restrict stats creation
   to a subset of connections (e.g. only those sourced from the host, or only
   those crossing towards another node or the external world) to bound the
   map size and the per-packet cost, or is accounting every tracked connection
   with API-side filtering (already supported by `filter`) enough for the
   first release? See [Future work](#future-work).

Other ideas are very welcome, thanks in advance folks.

## Future work

* Scope the datapath accounting to a subset of connections instead of every
  tracked one, for operators who only care about node-level egress rather
  than all cluster traffic. This also shrinks the map size and the per-packet
  cost, so it is a direct lever on the [end-to-end cost](#open-questions) and
  on the [default map size](#open-questions) questions above. The source side
  is close to free: `src_sec_id` is already resident at the CT create/lookup
  call sites that this CFP hooks into, so e.g. "only connections sourced from
  the host" needs no extra lookup. The destination side (e.g. "only towards a
  remote node or the external world") is not free today, because the already
  resolved destination identity isn't threaded down to those call sites; it
  would need to be passed in by the caller rather than looked up again.
* Revisit the counting scheme with the end-to-end numbers. If they call for it,
  add a flag to choose between `percpu` (more memory, less CPU) and `atomic`
  (less memory, more CPU), or a sampled variant.
* Attribute services to the regular entry and drop the `TUPLE_F_SERVICE`
  accounting.
* Socket-LB traffic: map backends to services from the control plane. This is
  ambiguous when a backend belongs to several services.
* Converge with `bpf-conntrack-accounting` and free the room in the CT entry
  for new data (e.g. policy cookie).
* Push selective filters down to the agents.
* Cluster Mesh: resolve cluster-scoped nodes.
* Consumers: service-map volumes in Hubble UI, a top-N exporter for Prometheus,
  rates computed between snapshots.

## Appendix: benchmarks

Average ns per packet, lower is better, CPU governor `performance`, 3M
repetitions. A run with no counter update takes 10-19 ns.

All the numbers come from a single laptop: Intel Core Ultra 7 165H (16 cores,
22 threads, hybrid P/E cores, 24 MiB L3), 30 GiB of RAM, Linux 6.17. Hybrid
cores and a single machine mean that absolute numbers will differ elsewhere, so
they are meant to compare the schemes with each other, not to predict the
overhead on a production node.

Hit path, common LRU, no eviction:

| Scenario | percpu | cpukey | atomic | atomicdir |
|---|---|---|---|---|
| 2 CPUs, 1 flow | 25 | 26 | 70 | 33 |
| 2 CPUs, 16 flows | 26 | 27 | 49 | 33 |
| 4 CPUs, 1 flow | 27 | 27 | 133 | 74 |
| 4 CPUs, 16 flows | 26 | 27 | 59 | 58 |
| RSS, 4 CPUs, 1024 flows | 37 | 43 | 62 | 55 |
| RSS, 6 CPUs, 1024 flows | 39 | 38 | 65 | 58 |
| same flow, 6 CPUs, 1024 flows | 33 | 32 | 46 | 57 |

Eviction, 65k flows over a 1024-entry map:

| Scenario | percpu | cpukey | atomic | atomicdir |
|---|---|---|---|---|
| common LRU, RSS 4 CPUs | 850 | 584 | 599 | 611 |
| common LRU, RSS 6 CPUs | 1411 | 1281 | 1312 | 1022 |
| common LRU, same flow 6 CPUs | 1416 | 1279 | 1314 | 1024 |
| `NO_COMMON_LRU`, RSS 4 CPUs | 285 | 131 | 130 | 131 |
| `NO_COMMON_LRU`, RSS 6 CPUs | 303 | 147 | 147 | 149 |
| `NO_COMMON_LRU`, same flow 6 CPUs | 298 | 144 | 144 | 144 |
