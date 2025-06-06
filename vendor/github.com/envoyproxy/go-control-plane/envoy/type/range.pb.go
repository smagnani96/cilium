// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.30.0
// 	protoc        v5.29.3
// source: envoy/type/range.proto

package _type

import (
	_ "github.com/cncf/xds/go/udpa/annotations"
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

// Specifies the int64 start and end of the range using half-open interval semantics [start,
// end).
type Int64Range struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// start of the range (inclusive)
	Start int64 `protobuf:"varint,1,opt,name=start,proto3" json:"start,omitempty"`
	// end of the range (exclusive)
	End int64 `protobuf:"varint,2,opt,name=end,proto3" json:"end,omitempty"`
}

func (x *Int64Range) Reset() {
	*x = Int64Range{}
	if protoimpl.UnsafeEnabled {
		mi := &file_envoy_type_range_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Int64Range) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Int64Range) ProtoMessage() {}

func (x *Int64Range) ProtoReflect() protoreflect.Message {
	mi := &file_envoy_type_range_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Int64Range.ProtoReflect.Descriptor instead.
func (*Int64Range) Descriptor() ([]byte, []int) {
	return file_envoy_type_range_proto_rawDescGZIP(), []int{0}
}

func (x *Int64Range) GetStart() int64 {
	if x != nil {
		return x.Start
	}
	return 0
}

func (x *Int64Range) GetEnd() int64 {
	if x != nil {
		return x.End
	}
	return 0
}

// Specifies the int32 start and end of the range using half-open interval semantics [start,
// end).
type Int32Range struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// start of the range (inclusive)
	Start int32 `protobuf:"varint,1,opt,name=start,proto3" json:"start,omitempty"`
	// end of the range (exclusive)
	End int32 `protobuf:"varint,2,opt,name=end,proto3" json:"end,omitempty"`
}

func (x *Int32Range) Reset() {
	*x = Int32Range{}
	if protoimpl.UnsafeEnabled {
		mi := &file_envoy_type_range_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Int32Range) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Int32Range) ProtoMessage() {}

func (x *Int32Range) ProtoReflect() protoreflect.Message {
	mi := &file_envoy_type_range_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Int32Range.ProtoReflect.Descriptor instead.
func (*Int32Range) Descriptor() ([]byte, []int) {
	return file_envoy_type_range_proto_rawDescGZIP(), []int{1}
}

func (x *Int32Range) GetStart() int32 {
	if x != nil {
		return x.Start
	}
	return 0
}

func (x *Int32Range) GetEnd() int32 {
	if x != nil {
		return x.End
	}
	return 0
}

// Specifies the double start and end of the range using half-open interval semantics [start,
// end).
type DoubleRange struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// start of the range (inclusive)
	Start float64 `protobuf:"fixed64,1,opt,name=start,proto3" json:"start,omitempty"`
	// end of the range (exclusive)
	End float64 `protobuf:"fixed64,2,opt,name=end,proto3" json:"end,omitempty"`
}

func (x *DoubleRange) Reset() {
	*x = DoubleRange{}
	if protoimpl.UnsafeEnabled {
		mi := &file_envoy_type_range_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *DoubleRange) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*DoubleRange) ProtoMessage() {}

func (x *DoubleRange) ProtoReflect() protoreflect.Message {
	mi := &file_envoy_type_range_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use DoubleRange.ProtoReflect.Descriptor instead.
func (*DoubleRange) Descriptor() ([]byte, []int) {
	return file_envoy_type_range_proto_rawDescGZIP(), []int{2}
}

func (x *DoubleRange) GetStart() float64 {
	if x != nil {
		return x.Start
	}
	return 0
}

func (x *DoubleRange) GetEnd() float64 {
	if x != nil {
		return x.End
	}
	return 0
}

var File_envoy_type_range_proto protoreflect.FileDescriptor

var file_envoy_type_range_proto_rawDesc = []byte{
	0x0a, 0x16, 0x65, 0x6e, 0x76, 0x6f, 0x79, 0x2f, 0x74, 0x79, 0x70, 0x65, 0x2f, 0x72, 0x61, 0x6e,
	0x67, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x0a, 0x65, 0x6e, 0x76, 0x6f, 0x79, 0x2e,
	0x74, 0x79, 0x70, 0x65, 0x1a, 0x1d, 0x75, 0x64, 0x70, 0x61, 0x2f, 0x61, 0x6e, 0x6e, 0x6f, 0x74,
	0x61, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x2f, 0x73, 0x74, 0x61, 0x74, 0x75, 0x73, 0x2e, 0x70, 0x72,
	0x6f, 0x74, 0x6f, 0x22, 0x34, 0x0a, 0x0a, 0x49, 0x6e, 0x74, 0x36, 0x34, 0x52, 0x61, 0x6e, 0x67,
	0x65, 0x12, 0x14, 0x0a, 0x05, 0x73, 0x74, 0x61, 0x72, 0x74, 0x18, 0x01, 0x20, 0x01, 0x28, 0x03,
	0x52, 0x05, 0x73, 0x74, 0x61, 0x72, 0x74, 0x12, 0x10, 0x0a, 0x03, 0x65, 0x6e, 0x64, 0x18, 0x02,
	0x20, 0x01, 0x28, 0x03, 0x52, 0x03, 0x65, 0x6e, 0x64, 0x22, 0x34, 0x0a, 0x0a, 0x49, 0x6e, 0x74,
	0x33, 0x32, 0x52, 0x61, 0x6e, 0x67, 0x65, 0x12, 0x14, 0x0a, 0x05, 0x73, 0x74, 0x61, 0x72, 0x74,
	0x18, 0x01, 0x20, 0x01, 0x28, 0x05, 0x52, 0x05, 0x73, 0x74, 0x61, 0x72, 0x74, 0x12, 0x10, 0x0a,
	0x03, 0x65, 0x6e, 0x64, 0x18, 0x02, 0x20, 0x01, 0x28, 0x05, 0x52, 0x03, 0x65, 0x6e, 0x64, 0x22,
	0x35, 0x0a, 0x0b, 0x44, 0x6f, 0x75, 0x62, 0x6c, 0x65, 0x52, 0x61, 0x6e, 0x67, 0x65, 0x12, 0x14,
	0x0a, 0x05, 0x73, 0x74, 0x61, 0x72, 0x74, 0x18, 0x01, 0x20, 0x01, 0x28, 0x01, 0x52, 0x05, 0x73,
	0x74, 0x61, 0x72, 0x74, 0x12, 0x10, 0x0a, 0x03, 0x65, 0x6e, 0x64, 0x18, 0x02, 0x20, 0x01, 0x28,
	0x01, 0x52, 0x03, 0x65, 0x6e, 0x64, 0x42, 0x63, 0xba, 0x80, 0xc8, 0xd1, 0x06, 0x02, 0x10, 0x01,
	0x0a, 0x18, 0x69, 0x6f, 0x2e, 0x65, 0x6e, 0x76, 0x6f, 0x79, 0x70, 0x72, 0x6f, 0x78, 0x79, 0x2e,
	0x65, 0x6e, 0x76, 0x6f, 0x79, 0x2e, 0x74, 0x79, 0x70, 0x65, 0x42, 0x0a, 0x52, 0x61, 0x6e, 0x67,
	0x65, 0x50, 0x72, 0x6f, 0x74, 0x6f, 0x50, 0x01, 0x5a, 0x31, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62,
	0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x65, 0x6e, 0x76, 0x6f, 0x79, 0x70, 0x72, 0x6f, 0x78, 0x79, 0x2f,
	0x67, 0x6f, 0x2d, 0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x2d, 0x70, 0x6c, 0x61, 0x6e, 0x65,
	0x2f, 0x65, 0x6e, 0x76, 0x6f, 0x79, 0x2f, 0x74, 0x79, 0x70, 0x65, 0x62, 0x06, 0x70, 0x72, 0x6f,
	0x74, 0x6f, 0x33,
}

var (
	file_envoy_type_range_proto_rawDescOnce sync.Once
	file_envoy_type_range_proto_rawDescData = file_envoy_type_range_proto_rawDesc
)

func file_envoy_type_range_proto_rawDescGZIP() []byte {
	file_envoy_type_range_proto_rawDescOnce.Do(func() {
		file_envoy_type_range_proto_rawDescData = protoimpl.X.CompressGZIP(file_envoy_type_range_proto_rawDescData)
	})
	return file_envoy_type_range_proto_rawDescData
}

var file_envoy_type_range_proto_msgTypes = make([]protoimpl.MessageInfo, 3)
var file_envoy_type_range_proto_goTypes = []interface{}{
	(*Int64Range)(nil),  // 0: envoy.type.Int64Range
	(*Int32Range)(nil),  // 1: envoy.type.Int32Range
	(*DoubleRange)(nil), // 2: envoy.type.DoubleRange
}
var file_envoy_type_range_proto_depIdxs = []int32{
	0, // [0:0] is the sub-list for method output_type
	0, // [0:0] is the sub-list for method input_type
	0, // [0:0] is the sub-list for extension type_name
	0, // [0:0] is the sub-list for extension extendee
	0, // [0:0] is the sub-list for field type_name
}

func init() { file_envoy_type_range_proto_init() }
func file_envoy_type_range_proto_init() {
	if File_envoy_type_range_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_envoy_type_range_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Int64Range); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_envoy_type_range_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Int32Range); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_envoy_type_range_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*DoubleRange); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_envoy_type_range_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   3,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_envoy_type_range_proto_goTypes,
		DependencyIndexes: file_envoy_type_range_proto_depIdxs,
		MessageInfos:      file_envoy_type_range_proto_msgTypes,
	}.Build()
	File_envoy_type_range_proto = out.File
	file_envoy_type_range_proto_rawDesc = nil
	file_envoy_type_range_proto_goTypes = nil
	file_envoy_type_range_proto_depIdxs = nil
}
