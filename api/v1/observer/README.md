# Protocol Documentation
<a name="top"></a>

## Table of Contents

- [observer/observer.proto](#observer_observer-proto)
    - [ConntrackFilter](#observer-ConntrackFilter)
    - [ConntrackStatsEndpoint](#observer-ConntrackStatsEndpoint)
    - [ConntrackStatsEntry](#observer-ConntrackStatsEntry)
    - [ConntrackStatsKey](#observer-ConntrackStatsKey)
    - [ConntrackStatsNode](#observer-ConntrackStatsNode)
    - [ConntrackStatsValue](#observer-ConntrackStatsValue)
    - [ExportEvent](#observer-ExportEvent)
    - [GetAgentEventsRequest](#observer-GetAgentEventsRequest)
    - [GetAgentEventsResponse](#observer-GetAgentEventsResponse)
    - [GetConntrackStatsRequest](#observer-GetConntrackStatsRequest)
    - [GetConntrackStatsResponse](#observer-GetConntrackStatsResponse)
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
  
    - [ConntrackAggregationField](#observer-ConntrackAggregationField)
  
    - [Observer](#observer-Observer)
  
- [Scalar Value Types](#scalar-value-types)



<a name="observer_observer-proto"></a>
<p align="right"><a href="#top">Top</a></p>

## observer/observer.proto



<a name="observer-ConntrackFilter"></a>

### ConntrackFilter
ConntrackFilter narrows down a GetConntrackStats response to only the
entries that match every field it sets: a repeated field matches if the
entry&#39;s corresponding value equals any one of the listed values (i.e. an
OR across a field&#39;s own values, an AND across different fields). Unset
(empty) fields impose no constraint. Filtering is applied before
aggregation, so group_by only ever sums entries that already passed the
filter.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| source_ip | [string](#string) | repeated | source_ip/destination_ip match either an exact address (e.g. &#34;10.0.0.1&#34;) or a CIDR range (e.g. &#34;10.0.0.0/24&#34;). |
| destination_ip | [string](#string) | repeated |  |
| source_port | [uint32](#uint32) | repeated |  |
| destination_port | [uint32](#uint32) | repeated |  |
| protocol | [uint32](#uint32) | repeated |  |
| source_endpoint | [string](#string) | repeated | source_endpoint/destination_endpoint match the resolved source/destination Endpoint&#39;s namespace and name, using the same &#34;[&lt;namespace&gt;/]&lt;name-prefix&gt;&#34;. Namespace, if given, must match exactly, and name, if given, is matched as a prefix. An entry whose corresponding side didn&#39;t resolve to an Endpoint never matches. |
| destination_endpoint | [string](#string) | repeated |  |
| source_node | [string](#string) | repeated | source_node/destination_node match the resolved source/destination node&#39;s name exactly using the convention &#34;[cluster/]&lt;name-prefix&gt;&#34;. An entry whose corresponding side didn&#39;t resolve to a node never matches. |
| destination_node | [string](#string) | repeated |  |






<a name="observer-ConntrackStatsEndpoint"></a>

### ConntrackStatsEndpoint
ConntrackStatsEndpoint carries a single resolved source or destination
flow.Endpoint referenced by one or more ConntrackStatsEntry messages, alongside
the index they reference it by.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| index | [uint32](#uint32) |  |  |
| endpoint | [flow.Endpoint](#flow-Endpoint) |  |  |






<a name="observer-ConntrackStatsEntry"></a>

### ConntrackStatsEntry
ConntrackStatsEntry is an entry from a node&#39;s datapath conntrack map.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| key | [ConntrackStatsKey](#observer-ConntrackStatsKey) |  |  |
| value | [ConntrackStatsValue](#observer-ConntrackStatsValue) |  |  |
| source_endpoint_index | [google.protobuf.UInt32Value](#google-protobuf-UInt32Value) |  | source_endpoint_index/destination_endpoint_index reference, by index, a ConntrackStatsEndpoint message carrying the resolved source/destination flow.Endpoint for this entry. They are unset if resolution failed. |
| destination_endpoint_index | [google.protobuf.UInt32Value](#google-protobuf-UInt32Value) |  |  |
| source_node_index | [google.protobuf.UInt32Value](#google-protobuf-UInt32Value) |  | source_node_index/destination_node_index reference, by index, a ConntrackStatsNode message carrying the resolved source/destination node for this entry. They are unset if resolution failed. |
| destination_node_index | [google.protobuf.UInt32Value](#google-protobuf-UInt32Value) |  |  |
| count | [uint64](#uint64) |  |  |






<a name="observer-ConntrackStatsKey"></a>

### ConntrackStatsKey
ConntrackStatsKey represents the key of a conntrack stats entry.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| source_ip | [string](#string) |  |  |
| source_port | [uint32](#uint32) |  |  |
| destination_ip | [string](#string) |  |  |
| destination_port | [uint32](#uint32) |  |  |
| protocol | [uint32](#uint32) |  |  |
| flags | [uint32](#uint32) |  | flags is used only for internal purposes. TUPLE_F_SERVICE: will never appeared, as we&#39;re skipping CT_SERVICE direction in the datapath. TUPLE_F_IN: is ok as is, nothing special. TUPLE_F_OUT: is ok as is, nothing special. TUPLE_F_IN: is the exact copy of TUPLE_F_OUT but with reversed per-direction counters. We keep only one between the two. To do so, we must not lose this flag before aggregation. |






<a name="observer-ConntrackStatsNode"></a>

### ConntrackStatsNode
ConntrackStatsNode carries a single resolved source or destination cluster
node referenced by one or more ConntrackStatsEntry messages, alongside the
index they reference it by.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| index | [uint32](#uint32) |  |  |
| name | [string](#string) |  |  |
| cluster | [string](#string) |  |  |
| labels | [string](#string) | repeated |  |






<a name="observer-ConntrackStatsValue"></a>

### ConntrackStatsValue
ConntrackStatsValue represents the value of a conntrack stats entry.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| rx_packets | [uint64](#uint64) |  |  |
| tx_packets | [uint64](#uint64) |  |  |
| rx_bytes | [uint64](#uint64) |  |  |
| tx_bytes | [uint64](#uint64) |  |  |






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






<a name="observer-GetConntrackStatsRequest"></a>

### GetConntrackStatsRequest



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| group_by | [ConntrackAggregationField](#observer-ConntrackAggregationField) | repeated | group_by, if non-empty, aggregates entries server-side before they are streamed back: entries that agree on every field listed here are merged into a single ConntrackStatsEntry with summed counters, and every field *not* listed is cleared. Aggregation is computed fresh for each request from the underlying cached stats. |
| filter | [ConntrackFilter](#observer-ConntrackFilter) |  | filter, if set, drops every entry that doesn&#39;t match it before group_by is applied. As with group_by, filtering is applied fresh for each request against the underlying cached stats. |






<a name="observer-GetConntrackStatsResponse"></a>

### GetConntrackStatsResponse
GetConntrackStatsResponse streams the entries themselves, or a status update
about the node. A header is always sent before the entries it applies to.
Every ConntrackStatsEndpoint referenced by an entry&#39;s source_endpoint_index or
destination_endpoint_index, and every ConntrackStatsNode referenced by an
entry&#39;s source_node_index or destination_node_index, is guaranteed to have
been sent earlier in the same response stream.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| entry | [ConntrackStatsEntry](#observer-ConntrackStatsEntry) |  |  |
| node_status | [relay.NodeStatusEvent](#relay-NodeStatusEvent) |  |  |
| endpoint | [ConntrackStatsEndpoint](#observer-ConntrackStatsEndpoint) |  |  |
| node | [ConntrackStatsNode](#observer-ConntrackStatsNode) |  |  |






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





 


<a name="observer-ConntrackAggregationField"></a>

### ConntrackAggregationField
ConntrackAggregationField selects one field to keep distinct when
GetConntrackStatsRequest.group_by requests server-side aggregation.

| Name | Number | Description |
| ---- | ------ | ----------- |
| CONNTRACK_AGGREGATION_FIELD_UNKNOWN | 0 |  |
| CONNTRACK_AGGREGATION_FIELD_SOURCE_IP | 1 |  |
| CONNTRACK_AGGREGATION_FIELD_SOURCE_PORT | 2 |  |
| CONNTRACK_AGGREGATION_FIELD_DESTINATION_IP | 3 |  |
| CONNTRACK_AGGREGATION_FIELD_DESTINATION_PORT | 4 |  |
| CONNTRACK_AGGREGATION_FIELD_PROTOCOL | 5 |  |
| CONNTRACK_AGGREGATION_FIELD_SOURCE_ENDPOINT | 6 | The following values group by the *resolved* source/destination Endpoint or node identity instead of the raw source/destination IP. Entries whose corresponding side didn&#39;t resolve to an Endpoint or node are grouped together into a single &#34;unresolved&#34; bucket rather than dropped. |
| CONNTRACK_AGGREGATION_FIELD_DESTINATION_ENDPOINT | 7 |  |
| CONNTRACK_AGGREGATION_FIELD_SOURCE_NODE | 8 |  |
| CONNTRACK_AGGREGATION_FIELD_DESTINATION_NODE | 9 |  |


 

 


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
| GetConntrackStats | [GetConntrackStatsRequest](#observer-GetConntrackStatsRequest) | [GetConntrackStatsResponse](#observer-GetConntrackStatsResponse) stream | GetConntrackStats returns the connection tracking stats currently present in the node&#39;s datapath conntrack maps. Because the underlying maps are LRU-based, the result is a best-effort snapshot: entries may be evicted or added while it is being produced. |

 



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

