// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.25.0
// 	protoc        v3.13.0
// source: evss.proto

package proto

// import (
// 	proto "github.com/golang/protobuf/proto"
// 	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
// 	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
// 	reflect "reflect"
// 	sync "sync"
// )

// const (
// 	// Verify that this generated code is sufficiently up-to-date.
// 	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
// 	// Verify that runtime/protoimpl is sufficiently up-to-date.
// 	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
// )

// // This is a compile-time assertion that a sufficiently up-to-date version
// // of the legacy proto package is being used.
// const _ = proto.ProtoPackageIsVersion4

// type PublicInfo struct {
// 	state         protoimpl.MessageState
// 	sizeCache     protoimpl.SizeCache
// 	unknownFields protoimpl.UnknownFields

// 	Pk     []byte `protobuf:"bytes,1,opt,name=pk,proto3" json:"pk,omitempty"`
// 	Commit []byte `protobuf:"bytes,2,opt,name=commit,proto3" json:"commit,omitempty"`
// }

// func (x *PublicInfo) Reset() {
// 	*x = PublicInfo{}
// 	if protoimpl.UnsafeEnabled {
// 		mi := &file_evss_proto_msgTypes[0]
// 		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
// 		ms.StoreMessageInfo(mi)
// 	}
// }

// func (x *PublicInfo) String() string {
// 	return protoimpl.X.MessageStringOf(x)
// }

// func (*PublicInfo) ProtoMessage() {}

// func (x *PublicInfo) ProtoReflect() protoreflect.Message {
// 	mi := &file_evss_proto_msgTypes[0]
// 	if protoimpl.UnsafeEnabled && x != nil {
// 		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
// 		if ms.LoadMessageInfo() == nil {
// 			ms.StoreMessageInfo(mi)
// 		}
// 		return ms
// 	}
// 	return mi.MessageOf(x)
// }

// // Deprecated: Use PublicInfo.ProtoReflect.Descriptor instead.
// func (*PublicInfo) Descriptor() ([]byte, []int) {
// 	return file_evss_proto_rawDescGZIP(), []int{0}
// }

// func (x *PublicInfo) GetPk() []byte {
// 	if x != nil {
// 		return x.Pk
// 	}
// 	return nil
// }

// func (x *PublicInfo) GetCommit() []byte {
// 	if x != nil {
// 		return x.Commit
// 	}
// 	return nil
// }

// type Share struct {
// 	state         protoimpl.MessageState
// 	sizeCache     protoimpl.SizeCache
// 	unknownFields protoimpl.UnknownFields

// 	Index   []byte `protobuf:"bytes,1,opt,name=Index,proto3" json:"Index,omitempty"`
// 	Result  []byte `protobuf:"bytes,2,opt,name=Result,proto3" json:"Result,omitempty"`
// 	Witness []byte `protobuf:"bytes,3,opt,name=Witness,proto3" json:"Witness,omitempty"`
// }

// func (x *Share) Reset() {
// 	*x = Share{}
// 	if protoimpl.UnsafeEnabled {
// 		mi := &file_evss_proto_msgTypes[1]
// 		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
// 		ms.StoreMessageInfo(mi)
// 	}
// }

// func (x *Share) String() string {
// 	return protoimpl.X.MessageStringOf(x)
// }

// func (*Share) ProtoMessage() {}

// func (x *Share) ProtoReflect() protoreflect.Message {
// 	mi := &file_evss_proto_msgTypes[1]
// 	if protoimpl.UnsafeEnabled && x != nil {
// 		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
// 		if ms.LoadMessageInfo() == nil {
// 			ms.StoreMessageInfo(mi)
// 		}
// 		return ms
// 	}
// 	return mi.MessageOf(x)
// }

// // Deprecated: Use Share.ProtoReflect.Descriptor instead.
// func (*Share) Descriptor() ([]byte, []int) {
// 	return file_evss_proto_rawDescGZIP(), []int{1}
// }

// func (x *Share) GetIndex() []byte {
// 	if x != nil {
// 		return x.Index
// 	}
// 	return nil
// }

// func (x *Share) GetResult() []byte {
// 	if x != nil {
// 		return x.Result
// 	}
// 	return nil
// }

// func (x *Share) GetWitness() []byte {
// 	if x != nil {
// 		return x.Witness
// 	}
// 	return nil
// }

// var File_evss_proto protoreflect.FileDescriptor

// var file_evss_proto_rawDesc = []byte{
// 	0x0a, 0x0a, 0x65, 0x76, 0x73, 0x73, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x05, 0x70, 0x72,
// 	0x6f, 0x74, 0x6f, 0x1a, 0x10, 0x70, 0x6f, 0x6c, 0x79, 0x63, 0x6f, 0x6d, 0x6d, 0x69, 0x74, 0x2e,
// 	0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0x34, 0x0a, 0x0a, 0x50, 0x75, 0x62, 0x6c, 0x69, 0x63, 0x49,
// 	0x6e, 0x66, 0x6f, 0x12, 0x0e, 0x0a, 0x02, 0x70, 0x6b, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0c, 0x52,
// 	0x02, 0x70, 0x6b, 0x12, 0x16, 0x0a, 0x06, 0x63, 0x6f, 0x6d, 0x6d, 0x69, 0x74, 0x18, 0x02, 0x20,
// 	0x01, 0x28, 0x0c, 0x52, 0x06, 0x63, 0x6f, 0x6d, 0x6d, 0x69, 0x74, 0x22, 0x4f, 0x0a, 0x05, 0x53,
// 	0x68, 0x61, 0x72, 0x65, 0x12, 0x14, 0x0a, 0x05, 0x49, 0x6e, 0x64, 0x65, 0x78, 0x18, 0x01, 0x20,
// 	0x01, 0x28, 0x0c, 0x52, 0x05, 0x49, 0x6e, 0x64, 0x65, 0x78, 0x12, 0x16, 0x0a, 0x06, 0x52, 0x65,
// 	0x73, 0x75, 0x6c, 0x74, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x06, 0x52, 0x65, 0x73, 0x75,
// 	0x6c, 0x74, 0x12, 0x18, 0x0a, 0x07, 0x57, 0x69, 0x74, 0x6e, 0x65, 0x73, 0x73, 0x18, 0x03, 0x20,
// 	0x01, 0x28, 0x0c, 0x52, 0x07, 0x57, 0x69, 0x74, 0x6e, 0x65, 0x73, 0x73, 0x42, 0x27, 0x5a, 0x25,
// 	0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x7a, 0x68, 0x74, 0x6c, 0x75,
// 	0x6f, 0x2f, 0x6c, 0x69, 0x62, 0x70, 0x6f, 0x6c, 0x79, 0x63, 0x72, 0x79, 0x70, 0x74, 0x6f, 0x2f,
// 	0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
// }

// var (
// 	file_evss_proto_rawDescOnce sync.Once
// 	file_evss_proto_rawDescData = file_evss_proto_rawDesc
// )

// func file_evss_proto_rawDescGZIP() []byte {
// 	file_evss_proto_rawDescOnce.Do(func() {
// 		file_evss_proto_rawDescData = protoimpl.X.CompressGZIP(file_evss_proto_rawDescData)
// 	})
// 	return file_evss_proto_rawDescData
// }

// var file_evss_proto_msgTypes = make([]protoimpl.MessageInfo, 2)
// var file_evss_proto_goTypes = []interface{}{
// 	(*PublicInfo)(nil), // 0: proto.PublicInfo
// 	(*Share)(nil),      // 1: proto.Share
// }
// var file_evss_proto_depIdxs = []int32{
// 	0, // [0:0] is the sub-list for method output_type
// 	0, // [0:0] is the sub-list for method input_type
// 	0, // [0:0] is the sub-list for extension type_name
// 	0, // [0:0] is the sub-list for extension extendee
// 	0, // [0:0] is the sub-list for field type_name
// }

// func init() { file_evss_proto_init() }
// func file_evss_proto_init() {
// 	if File_evss_proto != nil {
// 		return
// 	}
// 	file_polycommit_proto_init()
// 	if !protoimpl.UnsafeEnabled {
// 		file_evss_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
// 			switch v := v.(*PublicInfo); i {
// 			case 0:
// 				return &v.state
// 			case 1:
// 				return &v.sizeCache
// 			case 2:
// 				return &v.unknownFields
// 			default:
// 				return nil
// 			}
// 		}
// 		file_evss_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
// 			switch v := v.(*Share); i {
// 			case 0:
// 				return &v.state
// 			case 1:
// 				return &v.sizeCache
// 			case 2:
// 				return &v.unknownFields
// 			default:
// 				return nil
// 			}
// 		}
// 	}
// 	type x struct{}
// 	out := protoimpl.TypeBuilder{
// 		File: protoimpl.DescBuilder{
// 			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
// 			RawDescriptor: file_evss_proto_rawDesc,
// 			NumEnums:      0,
// 			NumMessages:   2,
// 			NumExtensions: 0,
// 			NumServices:   0,
// 		},
// 		GoTypes:           file_evss_proto_goTypes,
// 		DependencyIndexes: file_evss_proto_depIdxs,
// 		MessageInfos:      file_evss_proto_msgTypes,
// 	}.Build()
// 	File_evss_proto = out.File
// 	file_evss_proto_rawDesc = nil
// 	file_evss_proto_goTypes = nil
// 	file_evss_proto_depIdxs = nil
// }
