# Protocol Documentation
<a name="top"></a>

## Table of Contents

- [conntrack/conntrack.proto](#conntrack_conntrack-proto)
    - [Entry](#conntrack-Entry)
    - [GetStatsRequest](#conntrack-GetStatsRequest)
    - [GetStatsResponse](#conntrack-GetStatsResponse)
    - [Key](#conntrack-Key)
    - [State](#conntrack-State)
    - [Value](#conntrack-Value)
  
- [Scalar Value Types](#scalar-value-types)



<a name="conntrack_conntrack-proto"></a>
<p align="right"><a href="#top">Top</a></p>

## conntrack/conntrack.proto



<a name="conntrack-Entry"></a>

### Entry
Entry is an entry from a node&#39;s datapath conntrack stats map.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| key | [Key](#conntrack-Key) |  |  |
| value | [Value](#conntrack-Value) |  |  |
| state | [State](#conntrack-State) |  |  |






<a name="conntrack-GetStatsRequest"></a>

### GetStatsRequest
GetStatsRequest is the request of the Observer.GetConntrackStats RPC.






<a name="conntrack-GetStatsResponse"></a>

### GetStatsResponse
GetStatsResponse streams the entries themselves, or a status update about
the node. When served by Hubble Relay, entries from all the nodes are
aggregated and each node&#39;s issues are reported as node statuses.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| entry | [Entry](#conntrack-Entry) |  |  |
| node_status | [relay.NodeStatusEvent](#relay-NodeStatusEvent) |  |  |






<a name="conntrack-Key"></a>

### Key
Key represents the key of a conntrack stats entry.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| source_ip | [string](#string) |  |  |
| source_port | [uint32](#uint32) |  |  |
| destination_ip | [string](#string) |  |  |
| destination_port | [uint32](#uint32) |  |  |
| protocol | [uint32](#uint32) |  |  |
| flags | [uint32](#uint32) |  |  |






<a name="conntrack-State"></a>

### State
State is the state of the conntrack entry a stats entry belongs to.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| alive | [bool](#bool) |  |  |






<a name="conntrack-Value"></a>

### Value
Value represents the value of a conntrack stats entry.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| rx_packets | [uint64](#uint64) |  |  |
| tx_packets | [uint64](#uint64) |  |  |
| rx_bytes | [uint64](#uint64) |  |  |
| tx_bytes | [uint64](#uint64) |  |  |





 

 

 

 



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

