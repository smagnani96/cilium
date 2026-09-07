# Protocol Documentation
<a name="top"></a>

## Table of Contents

- [observer/observer.proto](#observer_observer-proto)
    - [ConntrackEntry](#observer-ConntrackEntry)
    - [ConntrackEntryFlags](#observer-ConntrackEntryFlags)
    - [ConntrackEntryTCP](#observer-ConntrackEntryTCP)
    - [ExportEvent](#observer-ExportEvent)
    - [GetAgentEventsRequest](#observer-GetAgentEventsRequest)
    - [GetAgentEventsResponse](#observer-GetAgentEventsResponse)
    - [GetConntrackEntriesRequest](#observer-GetConntrackEntriesRequest)
    - [GetConntrackEntriesResponse](#observer-GetConntrackEntriesResponse)
    - [GetDebugEventsRequest](#observer-GetDebugEventsRequest)
    - [GetDebugEventsResponse](#observer-GetDebugEventsResponse)
    - [GetFlowsRequest](#observer-GetFlowsRequest)
    - [GetFlowsRequest.Experimental](#observer-GetFlowsRequest-Experimental)
    - [GetFlowsResponse](#observer-GetFlowsResponse)
    - [GetNamespacesRequest](#observer-GetNamespacesRequest)
    - [GetNamespacesResponse](#observer-GetNamespacesResponse)
    - [GetNodesRequest](#observer-GetNodesRequest)
    - [GetNodesResponse](#observer-GetNodesResponse)
    - [Namespace](#observer-Namespace)
    - [Node](#observer-Node)
    - [ServerStatusRequest](#observer-ServerStatusRequest)
    - [ServerStatusResponse](#observer-ServerStatusResponse)
    - [TLS](#observer-TLS)
  
    - [Observer](#observer-Observer)
  
- [Scalar Value Types](#scalar-value-types)



<a name="observer_observer-proto"></a>
<p align="right"><a href="#top">Top</a></p>

## observer/observer.proto



<a name="observer-ConntrackEntry"></a>

### ConntrackEntry
ConntrackEntry is an entry from a node&#39;s datapath conntrack
map (see pkg/maps/ctmap).


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| source_ip | [string](#string) |  |  |
| destination_ip | [string](#string) |  |  |
| source_port | [uint32](#uint32) |  |  |
| destination_port | [uint32](#uint32) |  |  |
| protocol | [uint32](#uint32) |  | IP protocol number (e.g. 6 for TCP, 17 for UDP). |
| direction | [flow.TrafficDirection](#flow-TrafficDirection) |  |  |
| packets | [uint64](#uint64) |  |  |
| bytes | [uint64](#uint64) |  |  |
| expires_at | [google.protobuf.Timestamp](#google-protobuf-Timestamp) |  | expires_at is the wall-clock time at which this entry is expected to expire. The datapath itself only records this in kernel-clock units local to this node (see pkg/maps/timestamp) with no shared reference an external reader could interpret, so it&#39;s converted to wall-clock time here, using this node&#39;s clock source at read time. Unset if the conversion failed. |
| flags | [ConntrackEntryFlags](#observer-ConntrackEntryFlags) |  | flags carried by this entry, decoded from struct ct_entry&#39;s flags bitfield (bpf/lib/conntrack.h). |
| tcp | [ConntrackEntryTCP](#observer-ConntrackEntryTCP) |  | tcp holds TCP-specific state. Unset for non-TCP entries (see struct ct_entry in bpf/lib/conntrack.h). |
| last_tx_report_at | [google.protobuf.Timestamp](#google-protobuf-Timestamp) |  | last_tx_report_at/last_rx_report_at are the wall-clock times of the last transmit/receive TCP flag report for this entry, converted the same way as expires_at. Unset if the conversion failed. |
| last_rx_report_at | [google.protobuf.Timestamp](#google-protobuf-Timestamp) |  |  |
| related | [bool](#bool) |  | related reports whether this entry belongs to a connection related to another one (e.g. an ICMP error referencing a different connection). |
| service_entry | [bool](#bool) |  | service_entry reports whether this entry&#39;s tuple was recorded for a load-balanced service connection. |
| source | [flow.Endpoint](#flow-Endpoint) |  | source/destination are resolved from Cilium&#39;s identity/endpoint state at read time. Unset if the resolution failed. |
| destination | [flow.Endpoint](#flow-Endpoint) |  |  |
| service | [flow.Service](#flow-Service) |  | service and backend are resolved from rev_nat_index/backend_id, and are therefore authoritative regardless of which side of a NAT&#39;d connection the raw tuple currently represents. Unset if the corresponding ID is 0 or could not be resolved. |
| backend | [flow.Endpoint](#flow-Endpoint) |  |  |






<a name="observer-ConntrackEntryFlags"></a>

### ConntrackEntryFlags
ConntrackEntryFlags exposes struct ct_entry&#39;s per-connection state flags
(bpf/lib/conntrack.h) as named booleans.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| rx_closing | [bool](#bool) |  |  |
| tx_closing | [bool](#bool) |  |  |
| lb_loopback | [bool](#bool) |  |  |
| seen_non_syn | [bool](#bool) |  |  |
| node_port | [bool](#bool) |  |  |
| proxy_redirect | [bool](#bool) |  |  |
| dsr_internal | [bool](#bool) |  |  |
| from_l7lb | [bool](#bool) |  |  |
| from_tunnel | [bool](#bool) |  |  |






<a name="observer-ConntrackEntryTCP"></a>

### ConntrackEntryTCP
ConntrackEntryTCP holds TCP-specific per-connection state, only set on
ConntrackEntry.tcp for entries with protocol == TCP.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| tx_flags_seen | [uint32](#uint32) |  | tx_flags_seen/rx_flags_seen are the bitwise-OR of every TCP flags byte seen on transmit/receive for this connection (see struct ct_entry in bpf/lib/conntrack.h). |
| rx_flags_seen | [uint32](#uint32) |  |  |






<a name="observer-ExportEvent"></a>

### ExportEvent
ExportEvent contains an event to be exported. Not to be used outside of the
exporter feature.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| flow | [flow.Flow](#flow-Flow) |  |  |
| node_status | [relay.NodeStatusEvent](#relay-NodeStatusEvent) |  | node_status informs clients about the state of the nodes participating in this particular GetFlows request. |
| lost_events | [flow.LostEvent](#flow-LostEvent) |  | lost_events informs clients about events which got dropped due to a Hubble component being unavailable |
| agent_event | [flow.AgentEvent](#flow-AgentEvent) |  | agent_event informs clients about an event received from the Cilium agent. |
| debug_event | [flow.DebugEvent](#flow-DebugEvent) |  | debug_event contains Cilium datapath debug events |
| node_name | [string](#string) |  | Name of the node where this event was observed. |
| time | [google.protobuf.Timestamp](#google-protobuf-Timestamp) |  | Timestamp at which this event was observed. |






<a name="observer-GetAgentEventsRequest"></a>

### GetAgentEventsRequest



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| number | [uint64](#uint64) |  | Number of flows that should be returned. Incompatible with `since/until`. Defaults to the most recent (last) `number` events, unless `first` is true, then it will return the earliest `number` events. |
| first | [bool](#bool) |  | first specifies if we should look at the first `number` events or the last `number` of events. Incompatible with `follow`. |
| follow | [bool](#bool) |  | follow sets when the server should continue to stream agent events after printing the last N agent events. |
| since | [google.protobuf.Timestamp](#google-protobuf-Timestamp) |  | Since this time for returned agent events. Incompatible with `number`. |
| until | [google.protobuf.Timestamp](#google-protobuf-Timestamp) |  | Until this time for returned agent events. Incompatible with `number`. |






<a name="observer-GetAgentEventsResponse"></a>

### GetAgentEventsResponse
GetAgentEventsResponse contains an event received from the Cilium agent.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| agent_event | [flow.AgentEvent](#flow-AgentEvent) |  |  |
| node_name | [string](#string) |  | Name of the node where this event was observed. |
| time | [google.protobuf.Timestamp](#google-protobuf-Timestamp) |  | Timestamp at which this event was observed. |






<a name="observer-GetConntrackEntriesRequest"></a>

### GetConntrackEntriesRequest



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| number | [uint64](#uint64) |  | Maximum number of entries that should be returned. 0 means no limit. |
| node_name | [string](#string) |  | node_name, if set, restricts the dump to the node with this name. |






<a name="observer-GetConntrackEntriesResponse"></a>

### GetConntrackEntriesResponse
GetConntrackEntriesResponse contains either a single conntrack entry read
from the node&#39;s datapath conntrack maps, or a status update about one of
the nodes participating in the request.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| entry | [ConntrackEntry](#observer-ConntrackEntry) |  |  |
| node_status | [relay.NodeStatusEvent](#relay-NodeStatusEvent) |  | node_status informs clients about the state of the nodes participating in this particular GetConntrackEntries request. Only sent by Hubble Relay, e.g. when a node&#39;s own GetConntrackEntries call failed (see relay.NodeState.NODE_ERROR). |
| node_name | [string](#string) |  | Name of the node where this entry was observed. |
| time | [google.protobuf.Timestamp](#google-protobuf-Timestamp) |  | Timestamp at which this entry was read from the datapath. |






<a name="observer-GetDebugEventsRequest"></a>

### GetDebugEventsRequest



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| number | [uint64](#uint64) |  | Number of events that should be returned. Incompatible with `since/until`. Defaults to the most recent (last) `number` events, unless `first` is true, then it will return the earliest `number` events. |
| first | [bool](#bool) |  | first specifies if we should look at the first `number` events or the last `number` of events. Incompatible with `follow`. |
| follow | [bool](#bool) |  | follow sets when the server should continue to stream debug events after printing the last N debug events. |
| since | [google.protobuf.Timestamp](#google-protobuf-Timestamp) |  | Since this time for returned debug events. Incompatible with `number`. |
| until | [google.protobuf.Timestamp](#google-protobuf-Timestamp) |  | Until this time for returned debug events. Incompatible with `number`. |






<a name="observer-GetDebugEventsResponse"></a>

### GetDebugEventsResponse
GetDebugEventsResponse contains a Cilium datapath debug events.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| debug_event | [flow.DebugEvent](#flow-DebugEvent) |  |  |
| node_name | [string](#string) |  | Name of the node where this event was observed. |
| time | [google.protobuf.Timestamp](#google-protobuf-Timestamp) |  | Timestamp at which this event was observed. |






<a name="observer-GetFlowsRequest"></a>

### GetFlowsRequest



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| number | [uint64](#uint64) |  | Number of flows that should be returned. Incompatible with `since/until`. Defaults to the most recent (last) `number` flows, unless `first` is true, then it will return the earliest `number` flows. |
| first | [bool](#bool) |  | first specifies if we should look at the first `number` flows or the last `number` of flows. Incompatible with `follow`. |
| follow | [bool](#bool) |  | follow sets when the server should continue to stream flows after printing the last N flows. |
| blacklist | [flow.FlowFilter](#flow-FlowFilter) | repeated | blacklist defines a list of filters which have to match for a flow to be excluded from the result. If multiple blacklist filters are specified, only one of them has to match for a flow to be excluded. |
| whitelist | [flow.FlowFilter](#flow-FlowFilter) | repeated | whitelist defines a list of filters which have to match for a flow to be included in the result. If multiple whitelist filters are specified, only one of them has to match for a flow to be included. The whitelist and blacklist can both be specified. In such cases, the set of the returned flows is the set difference `whitelist - blacklist`. In other words, the result will contain all flows matched by the whitelist that are not also simultaneously matched by the blacklist. |
| since | [google.protobuf.Timestamp](#google-protobuf-Timestamp) |  | Since this time for returned flows. Incompatible with `number`. |
| until | [google.protobuf.Timestamp](#google-protobuf-Timestamp) |  | Until this time for returned flows. Incompatible with `number`. |
| field_mask | [google.protobuf.FieldMask](#google-protobuf-FieldMask) |  | FieldMask allows clients to limit flow&#39;s fields that will be returned. For example, {paths: [&#34;source.id&#34;, &#34;destination.id&#34;]} will return flows with only these two fields set. |
| experimental | [GetFlowsRequest.Experimental](#observer-GetFlowsRequest-Experimental) |  |  |
| extensions | [google.protobuf.Any](#google-protobuf-Any) |  | extensions can be used to add arbitrary additional metadata to GetFlowsRequest. This can be used to extend functionality for other Hubble compatible APIs, or experiment with new functionality without needing to change the public API. |






<a name="observer-GetFlowsRequest-Experimental"></a>

### GetFlowsRequest.Experimental
Experimental contains fields that are not stable yet. Support for
experimental features is always optional and subject to change.






<a name="observer-GetFlowsResponse"></a>

### GetFlowsResponse
GetFlowsResponse contains either a flow or a protocol message.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| flow | [flow.Flow](#flow-Flow) |  |  |
| node_status | [relay.NodeStatusEvent](#relay-NodeStatusEvent) |  | node_status informs clients about the state of the nodes participating in this particular GetFlows request. |
| lost_events | [flow.LostEvent](#flow-LostEvent) |  | lost_events informs clients about events which got dropped due to a Hubble component being unavailable |
| node_name | [string](#string) |  | Name of the node where this event was observed. |
| time | [google.protobuf.Timestamp](#google-protobuf-Timestamp) |  | Timestamp at which this event was observed. |






<a name="observer-GetNamespacesRequest"></a>

### GetNamespacesRequest







<a name="observer-GetNamespacesResponse"></a>

### GetNamespacesResponse
GetNamespacesResponse contains the list of namespaces.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| namespaces | [Namespace](#observer-Namespace) | repeated | Namespaces is a list of namespaces with flows |






<a name="observer-GetNodesRequest"></a>

### GetNodesRequest







<a name="observer-GetNodesResponse"></a>

### GetNodesResponse
GetNodesResponse contains the list of nodes.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| nodes | [Node](#observer-Node) | repeated | Nodes is an exhaustive list of nodes. |






<a name="observer-Namespace"></a>

### Namespace



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| cluster | [string](#string) |  |  |
| namespace | [string](#string) |  |  |






<a name="observer-Node"></a>

### Node
Node represents a cluster node.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| name | [string](#string) |  | Name is the name of the node. |
| version | [string](#string) |  | Version is the version of Cilium/Hubble as reported by the node. |
| address | [string](#string) |  | Address is the network address of the API endpoint. |
| state | [relay.NodeState](#relay-NodeState) |  | State represents the known state of the node. |
| tls | [TLS](#observer-TLS) |  | TLS reports TLS related information. |
| uptime_ns | [uint64](#uint64) |  | UptimeNS is the uptime of this instance in nanoseconds |
| num_flows | [uint64](#uint64) |  | number of currently captured flows |
| max_flows | [uint64](#uint64) |  | maximum capacity of the ring buffer |
| seen_flows | [uint64](#uint64) |  | total amount of flows observed since the observer was started |






<a name="observer-ServerStatusRequest"></a>

### ServerStatusRequest







<a name="observer-ServerStatusResponse"></a>

### ServerStatusResponse



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| num_flows | [uint64](#uint64) |  | number of currently captured flows In a multi-node context, this is the cumulative count of all captured flows. |
| max_flows | [uint64](#uint64) |  | maximum capacity of the ring buffer In a multi-node context, this is the aggregation of all ring buffers capacities. |
| seen_flows | [uint64](#uint64) |  | total amount of flows observed since the observer was started In a multi-node context, this is the aggregation of all flows that have been seen. |
| uptime_ns | [uint64](#uint64) |  | uptime of this observer instance in nanoseconds In a multi-node context, this field corresponds to the uptime of the longest living instance. |
| num_connected_nodes | [google.protobuf.UInt32Value](#google-protobuf-UInt32Value) |  | number of nodes for which a connection is established |
| num_unavailable_nodes | [google.protobuf.UInt32Value](#google-protobuf-UInt32Value) |  | number of nodes for which a connection cannot be established |
| unavailable_nodes | [string](#string) | repeated | list of nodes that are unavailable This list may not be exhaustive. |
| version | [string](#string) |  | Version is the version of Cilium/Hubble. |
| flows_rate | [double](#double) |  | Approximate rate of flows seen by Hubble per second over the last minute. In a multi-node context, this is the sum of all flows rates. |






<a name="observer-TLS"></a>

### TLS
TLS represents TLS information.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| enabled | [bool](#bool) |  | Enabled reports whether TLS is enabled or not. |
| server_name | [string](#string) |  | ServerName is the TLS server name that can be used as part of the TLS cert validation process. |





 

 

 


<a name="observer-Observer"></a>

### Observer
Observer returns a stream of Flows depending on which filter the user want
to observe.

| Method Name | Request Type | Response Type | Description |
| ----------- | ------------ | ------------- | ------------|
| GetFlows | [GetFlowsRequest](#observer-GetFlowsRequest) | [GetFlowsResponse](#observer-GetFlowsResponse) stream | GetFlows returning structured data, meant to eventually obsolete GetLastNFlows. |
| GetAgentEvents | [GetAgentEventsRequest](#observer-GetAgentEventsRequest) | [GetAgentEventsResponse](#observer-GetAgentEventsResponse) stream | GetAgentEvents returns Cilium agent events. |
| GetDebugEvents | [GetDebugEventsRequest](#observer-GetDebugEventsRequest) | [GetDebugEventsResponse](#observer-GetDebugEventsResponse) stream | GetDebugEvents returns Cilium datapath debug events. |
| GetNodes | [GetNodesRequest](#observer-GetNodesRequest) | [GetNodesResponse](#observer-GetNodesResponse) | GetNodes returns information about nodes in a cluster. |
| GetNamespaces | [GetNamespacesRequest](#observer-GetNamespacesRequest) | [GetNamespacesResponse](#observer-GetNamespacesResponse) | GetNamespaces returns information about namespaces in a cluster. The namespaces returned are namespaces which have had network flows in the last hour. The namespaces are returned sorted by cluster name and namespace in ascending order. |
| ServerStatus | [ServerStatusRequest](#observer-ServerStatusRequest) | [ServerStatusResponse](#observer-ServerStatusResponse) | ServerStatus returns some details about the running hubble server. |
| GetConntrackEntries | [GetConntrackEntriesRequest](#observer-GetConntrackEntriesRequest) | [GetConntrackEntriesResponse](#observer-GetConntrackEntriesResponse) stream | GetConntrackEntries returns the connection tracking entries currently present in the node&#39;s datapath conntrack maps. Because the underlying maps are LRU-based, the result is a best-effort snapshot: entries may be evicted or added while it is being produced. |

 



## Scalar Value Types

| .proto Type | Notes | C++ | Java | Python | Go | C# | PHP | Ruby |
| ----------- | ----- | --- | ---- | ------ | -- | -- | --- | ---- |
| <a name="double" /> double |  | double | double | float | float64 | double | float | Float |
| <a name="float" /> float |  | float | float | float | float32 | float | float | Float |
| <a name="int32" /> int32 | Uses variable-length encoding. Inefficient for encoding negative numbers – if your field is likely to have negative values, use sint32 instead. | int32 | int | int | int32 | int | integer | Bignum or Fixnum (as required) |
| <a name="int64" /> int64 | Uses variable-length encoding. Inefficient for encoding negative numbers – if your field is likely to have negative values, use sint64 instead. | int64 | long | int/long | int64 | long | integer/string | Bignum |
| <a name="uint32" /> uint32 | Uses variable-length encoding. | uint32 | int | int/long | uint32 | uint | integer | Bignum or Fixnum (as required) |
| <a name="uint64" /> uint64 | Uses variable-length encoding. | uint64 | long | int/long | uint64 | ulong | integer/string | Bignum or Fixnum (as required) |
| <a name="sint32" /> sint32 | Uses variable-length encoding. Signed int value. These more efficiently encode negative numbers than regular int32s. | int32 | int | int | int32 | int | integer | Bignum or Fixnum (as required) |
| <a name="sint64" /> sint64 | Uses variable-length encoding. Signed int value. These more efficiently encode negative numbers than regular int64s. | int64 | long | int/long | int64 | long | integer/string | Bignum |
| <a name="fixed32" /> fixed32 | Always four bytes. More efficient than uint32 if values are often greater than 2^28. | uint32 | int | int | uint32 | uint | integer | Bignum or Fixnum (as required) |
| <a name="fixed64" /> fixed64 | Always eight bytes. More efficient than uint64 if values are often greater than 2^56. | uint64 | long | int/long | uint64 | ulong | integer/string | Bignum |
| <a name="sfixed32" /> sfixed32 | Always four bytes. | int32 | int | int | int32 | int | integer | Bignum or Fixnum (as required) |
| <a name="sfixed64" /> sfixed64 | Always eight bytes. | int64 | long | int/long | int64 | long | integer/string | Bignum |
| <a name="bool" /> bool |  | bool | boolean | boolean | bool | bool | boolean | TrueClass/FalseClass |
| <a name="string" /> string | A string must always contain UTF-8 encoded or 7-bit ASCII text. | string | String | str/unicode | string | string | string | String (UTF-8) |
| <a name="bytes" /> bytes | May contain any arbitrary sequence of bytes. | string | ByteString | str | []byte | ByteString | string | String (ASCII-8BIT) |

