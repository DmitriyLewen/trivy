// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.34.0
// 	protoc        (unknown)
// source: rpc/scanner/service.proto

package scanner

import (
	common "github.com/aquasecurity/trivy/rpc/common"
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

type ScanRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Target     string       `protobuf:"bytes,1,opt,name=target,proto3" json:"target,omitempty"` // image name or tar file path
	ArtifactId string       `protobuf:"bytes,2,opt,name=artifact_id,json=artifactId,proto3" json:"artifact_id,omitempty"`
	BlobIds    []string     `protobuf:"bytes,3,rep,name=blob_ids,json=blobIds,proto3" json:"blob_ids,omitempty"`
	Options    *ScanOptions `protobuf:"bytes,4,opt,name=options,proto3" json:"options,omitempty"`
}

func (x *ScanRequest) Reset() {
	*x = ScanRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_rpc_scanner_service_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ScanRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ScanRequest) ProtoMessage() {}

func (x *ScanRequest) ProtoReflect() protoreflect.Message {
	mi := &file_rpc_scanner_service_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ScanRequest.ProtoReflect.Descriptor instead.
func (*ScanRequest) Descriptor() ([]byte, []int) {
	return file_rpc_scanner_service_proto_rawDescGZIP(), []int{0}
}

func (x *ScanRequest) GetTarget() string {
	if x != nil {
		return x.Target
	}
	return ""
}

func (x *ScanRequest) GetArtifactId() string {
	if x != nil {
		return x.ArtifactId
	}
	return ""
}

func (x *ScanRequest) GetBlobIds() []string {
	if x != nil {
		return x.BlobIds
	}
	return nil
}

func (x *ScanRequest) GetOptions() *ScanOptions {
	if x != nil {
		return x.Options
	}
	return nil
}

// cf.
// https://stackoverflow.com/questions/38886789/protobuf3-how-to-describe-map-of-repeated-string
type Licenses struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Names []string `protobuf:"bytes,1,rep,name=names,proto3" json:"names,omitempty"`
}

func (x *Licenses) Reset() {
	*x = Licenses{}
	if protoimpl.UnsafeEnabled {
		mi := &file_rpc_scanner_service_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Licenses) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Licenses) ProtoMessage() {}

func (x *Licenses) ProtoReflect() protoreflect.Message {
	mi := &file_rpc_scanner_service_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Licenses.ProtoReflect.Descriptor instead.
func (*Licenses) Descriptor() ([]byte, []int) {
	return file_rpc_scanner_service_proto_rawDescGZIP(), []int{1}
}

func (x *Licenses) GetNames() []string {
	if x != nil {
		return x.Names
	}
	return nil
}

type ScanOptions struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	PkgTypes            []string             `protobuf:"bytes,1,rep,name=pkg_types,json=pkgTypes,proto3" json:"pkg_types,omitempty"`
	Scanners            []string             `protobuf:"bytes,2,rep,name=scanners,proto3" json:"scanners,omitempty"`
	LicenseCategories   map[string]*Licenses `protobuf:"bytes,4,rep,name=license_categories,json=licenseCategories,proto3" json:"license_categories,omitempty" protobuf_key:"bytes,1,opt,name=key,proto3" protobuf_val:"bytes,2,opt,name=value,proto3"`
	IncludeDevDeps      bool                 `protobuf:"varint,5,opt,name=include_dev_deps,json=includeDevDeps,proto3" json:"include_dev_deps,omitempty"`
	PkgRelationships    []string             `protobuf:"bytes,6,rep,name=pkg_relationships,json=pkgRelationships,proto3" json:"pkg_relationships,omitempty"`
	Distro              *common.OS           `protobuf:"bytes,7,opt,name=distro,proto3" json:"distro,omitempty"`
	VulnSeveritySources []string             `protobuf:"bytes,8,rep,name=vuln_severity_sources,json=vulnSeveritySources,proto3" json:"vuln_severity_sources,omitempty"`
	LicenseFull         bool                 `protobuf:"varint,9,opt,name=license_full,json=licenseFull,proto3" json:"license_full,omitempty"`
}

func (x *ScanOptions) Reset() {
	*x = ScanOptions{}
	if protoimpl.UnsafeEnabled {
		mi := &file_rpc_scanner_service_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ScanOptions) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ScanOptions) ProtoMessage() {}

func (x *ScanOptions) ProtoReflect() protoreflect.Message {
	mi := &file_rpc_scanner_service_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ScanOptions.ProtoReflect.Descriptor instead.
func (*ScanOptions) Descriptor() ([]byte, []int) {
	return file_rpc_scanner_service_proto_rawDescGZIP(), []int{2}
}

func (x *ScanOptions) GetPkgTypes() []string {
	if x != nil {
		return x.PkgTypes
	}
	return nil
}

func (x *ScanOptions) GetScanners() []string {
	if x != nil {
		return x.Scanners
	}
	return nil
}

func (x *ScanOptions) GetLicenseCategories() map[string]*Licenses {
	if x != nil {
		return x.LicenseCategories
	}
	return nil
}

func (x *ScanOptions) GetIncludeDevDeps() bool {
	if x != nil {
		return x.IncludeDevDeps
	}
	return false
}

func (x *ScanOptions) GetPkgRelationships() []string {
	if x != nil {
		return x.PkgRelationships
	}
	return nil
}

func (x *ScanOptions) GetDistro() *common.OS {
	if x != nil {
		return x.Distro
	}
	return nil
}

func (x *ScanOptions) GetVulnSeveritySources() []string {
	if x != nil {
		return x.VulnSeveritySources
	}
	return nil
}

func (x *ScanOptions) GetLicenseFull() bool {
	if x != nil {
		return x.LicenseFull
	}
	return false
}

type ScanResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Os      *common.OS      `protobuf:"bytes,1,opt,name=os,proto3" json:"os,omitempty"`
	Results []*Result       `protobuf:"bytes,3,rep,name=results,proto3" json:"results,omitempty"`
	Layers  []*common.Layer `protobuf:"bytes,4,rep,name=layers,proto3" json:"layers,omitempty"`
}

func (x *ScanResponse) Reset() {
	*x = ScanResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_rpc_scanner_service_proto_msgTypes[3]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ScanResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ScanResponse) ProtoMessage() {}

func (x *ScanResponse) ProtoReflect() protoreflect.Message {
	mi := &file_rpc_scanner_service_proto_msgTypes[3]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ScanResponse.ProtoReflect.Descriptor instead.
func (*ScanResponse) Descriptor() ([]byte, []int) {
	return file_rpc_scanner_service_proto_rawDescGZIP(), []int{3}
}

func (x *ScanResponse) GetOs() *common.OS {
	if x != nil {
		return x.Os
	}
	return nil
}

func (x *ScanResponse) GetResults() []*Result {
	if x != nil {
		return x.Results
	}
	return nil
}

func (x *ScanResponse) GetLayers() []*common.Layer {
	if x != nil {
		return x.Layers
	}
	return nil
}

// Result is the same as github.com/aquasecurity/trivy/pkg/report.Result
type Result struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Target            string                             `protobuf:"bytes,1,opt,name=target,proto3" json:"target,omitempty"`
	Vulnerabilities   []*common.Vulnerability            `protobuf:"bytes,2,rep,name=vulnerabilities,proto3" json:"vulnerabilities,omitempty"`
	Misconfigurations []*common.DetectedMisconfiguration `protobuf:"bytes,4,rep,name=misconfigurations,proto3" json:"misconfigurations,omitempty"`
	Class             string                             `protobuf:"bytes,6,opt,name=class,proto3" json:"class,omitempty"`
	Type              string                             `protobuf:"bytes,3,opt,name=type,proto3" json:"type,omitempty"`
	Packages          []*common.Package                  `protobuf:"bytes,5,rep,name=packages,proto3" json:"packages,omitempty"`
	CustomResources   []*common.CustomResource           `protobuf:"bytes,7,rep,name=custom_resources,json=customResources,proto3" json:"custom_resources,omitempty"`
	Secrets           []*common.SecretFinding            `protobuf:"bytes,8,rep,name=secrets,proto3" json:"secrets,omitempty"`
	Licenses          []*common.DetectedLicense          `protobuf:"bytes,9,rep,name=licenses,proto3" json:"licenses,omitempty"`
}

func (x *Result) Reset() {
	*x = Result{}
	if protoimpl.UnsafeEnabled {
		mi := &file_rpc_scanner_service_proto_msgTypes[4]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Result) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Result) ProtoMessage() {}

func (x *Result) ProtoReflect() protoreflect.Message {
	mi := &file_rpc_scanner_service_proto_msgTypes[4]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Result.ProtoReflect.Descriptor instead.
func (*Result) Descriptor() ([]byte, []int) {
	return file_rpc_scanner_service_proto_rawDescGZIP(), []int{4}
}

func (x *Result) GetTarget() string {
	if x != nil {
		return x.Target
	}
	return ""
}

func (x *Result) GetVulnerabilities() []*common.Vulnerability {
	if x != nil {
		return x.Vulnerabilities
	}
	return nil
}

func (x *Result) GetMisconfigurations() []*common.DetectedMisconfiguration {
	if x != nil {
		return x.Misconfigurations
	}
	return nil
}

func (x *Result) GetClass() string {
	if x != nil {
		return x.Class
	}
	return ""
}

func (x *Result) GetType() string {
	if x != nil {
		return x.Type
	}
	return ""
}

func (x *Result) GetPackages() []*common.Package {
	if x != nil {
		return x.Packages
	}
	return nil
}

func (x *Result) GetCustomResources() []*common.CustomResource {
	if x != nil {
		return x.CustomResources
	}
	return nil
}

func (x *Result) GetSecrets() []*common.SecretFinding {
	if x != nil {
		return x.Secrets
	}
	return nil
}

func (x *Result) GetLicenses() []*common.DetectedLicense {
	if x != nil {
		return x.Licenses
	}
	return nil
}

var File_rpc_scanner_service_proto protoreflect.FileDescriptor

var file_rpc_scanner_service_proto_rawDesc = []byte{
	0x0a, 0x19, 0x72, 0x70, 0x63, 0x2f, 0x73, 0x63, 0x61, 0x6e, 0x6e, 0x65, 0x72, 0x2f, 0x73, 0x65,
	0x72, 0x76, 0x69, 0x63, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x10, 0x74, 0x72, 0x69,
	0x76, 0x79, 0x2e, 0x73, 0x63, 0x61, 0x6e, 0x6e, 0x65, 0x72, 0x2e, 0x76, 0x31, 0x1a, 0x18, 0x72,
	0x70, 0x63, 0x2f, 0x63, 0x6f, 0x6d, 0x6d, 0x6f, 0x6e, 0x2f, 0x73, 0x65, 0x72, 0x76, 0x69, 0x63,
	0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0x9a, 0x01, 0x0a, 0x0b, 0x53, 0x63, 0x61, 0x6e,
	0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x16, 0x0a, 0x06, 0x74, 0x61, 0x72, 0x67, 0x65,
	0x74, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x06, 0x74, 0x61, 0x72, 0x67, 0x65, 0x74, 0x12,
	0x1f, 0x0a, 0x0b, 0x61, 0x72, 0x74, 0x69, 0x66, 0x61, 0x63, 0x74, 0x5f, 0x69, 0x64, 0x18, 0x02,
	0x20, 0x01, 0x28, 0x09, 0x52, 0x0a, 0x61, 0x72, 0x74, 0x69, 0x66, 0x61, 0x63, 0x74, 0x49, 0x64,
	0x12, 0x19, 0x0a, 0x08, 0x62, 0x6c, 0x6f, 0x62, 0x5f, 0x69, 0x64, 0x73, 0x18, 0x03, 0x20, 0x03,
	0x28, 0x09, 0x52, 0x07, 0x62, 0x6c, 0x6f, 0x62, 0x49, 0x64, 0x73, 0x12, 0x37, 0x0a, 0x07, 0x6f,
	0x70, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x18, 0x04, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x1d, 0x2e, 0x74,
	0x72, 0x69, 0x76, 0x79, 0x2e, 0x73, 0x63, 0x61, 0x6e, 0x6e, 0x65, 0x72, 0x2e, 0x76, 0x31, 0x2e,
	0x53, 0x63, 0x61, 0x6e, 0x4f, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x52, 0x07, 0x6f, 0x70, 0x74,
	0x69, 0x6f, 0x6e, 0x73, 0x22, 0x20, 0x0a, 0x08, 0x4c, 0x69, 0x63, 0x65, 0x6e, 0x73, 0x65, 0x73,
	0x12, 0x14, 0x0a, 0x05, 0x6e, 0x61, 0x6d, 0x65, 0x73, 0x18, 0x01, 0x20, 0x03, 0x28, 0x09, 0x52,
	0x05, 0x6e, 0x61, 0x6d, 0x65, 0x73, 0x22, 0xeb, 0x03, 0x0a, 0x0b, 0x53, 0x63, 0x61, 0x6e, 0x4f,
	0x70, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x12, 0x1b, 0x0a, 0x09, 0x70, 0x6b, 0x67, 0x5f, 0x74, 0x79,
	0x70, 0x65, 0x73, 0x18, 0x01, 0x20, 0x03, 0x28, 0x09, 0x52, 0x08, 0x70, 0x6b, 0x67, 0x54, 0x79,
	0x70, 0x65, 0x73, 0x12, 0x1a, 0x0a, 0x08, 0x73, 0x63, 0x61, 0x6e, 0x6e, 0x65, 0x72, 0x73, 0x18,
	0x02, 0x20, 0x03, 0x28, 0x09, 0x52, 0x08, 0x73, 0x63, 0x61, 0x6e, 0x6e, 0x65, 0x72, 0x73, 0x12,
	0x63, 0x0a, 0x12, 0x6c, 0x69, 0x63, 0x65, 0x6e, 0x73, 0x65, 0x5f, 0x63, 0x61, 0x74, 0x65, 0x67,
	0x6f, 0x72, 0x69, 0x65, 0x73, 0x18, 0x04, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x34, 0x2e, 0x74, 0x72,
	0x69, 0x76, 0x79, 0x2e, 0x73, 0x63, 0x61, 0x6e, 0x6e, 0x65, 0x72, 0x2e, 0x76, 0x31, 0x2e, 0x53,
	0x63, 0x61, 0x6e, 0x4f, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x2e, 0x4c, 0x69, 0x63, 0x65, 0x6e,
	0x73, 0x65, 0x43, 0x61, 0x74, 0x65, 0x67, 0x6f, 0x72, 0x69, 0x65, 0x73, 0x45, 0x6e, 0x74, 0x72,
	0x79, 0x52, 0x11, 0x6c, 0x69, 0x63, 0x65, 0x6e, 0x73, 0x65, 0x43, 0x61, 0x74, 0x65, 0x67, 0x6f,
	0x72, 0x69, 0x65, 0x73, 0x12, 0x28, 0x0a, 0x10, 0x69, 0x6e, 0x63, 0x6c, 0x75, 0x64, 0x65, 0x5f,
	0x64, 0x65, 0x76, 0x5f, 0x64, 0x65, 0x70, 0x73, 0x18, 0x05, 0x20, 0x01, 0x28, 0x08, 0x52, 0x0e,
	0x69, 0x6e, 0x63, 0x6c, 0x75, 0x64, 0x65, 0x44, 0x65, 0x76, 0x44, 0x65, 0x70, 0x73, 0x12, 0x2b,
	0x0a, 0x11, 0x70, 0x6b, 0x67, 0x5f, 0x72, 0x65, 0x6c, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x68,
	0x69, 0x70, 0x73, 0x18, 0x06, 0x20, 0x03, 0x28, 0x09, 0x52, 0x10, 0x70, 0x6b, 0x67, 0x52, 0x65,
	0x6c, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x68, 0x69, 0x70, 0x73, 0x12, 0x28, 0x0a, 0x06, 0x64,
	0x69, 0x73, 0x74, 0x72, 0x6f, 0x18, 0x07, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x10, 0x2e, 0x74, 0x72,
	0x69, 0x76, 0x79, 0x2e, 0x63, 0x6f, 0x6d, 0x6d, 0x6f, 0x6e, 0x2e, 0x4f, 0x53, 0x52, 0x06, 0x64,
	0x69, 0x73, 0x74, 0x72, 0x6f, 0x12, 0x32, 0x0a, 0x15, 0x76, 0x75, 0x6c, 0x6e, 0x5f, 0x73, 0x65,
	0x76, 0x65, 0x72, 0x69, 0x74, 0x79, 0x5f, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x73, 0x18, 0x08,
	0x20, 0x03, 0x28, 0x09, 0x52, 0x13, 0x76, 0x75, 0x6c, 0x6e, 0x53, 0x65, 0x76, 0x65, 0x72, 0x69,
	0x74, 0x79, 0x53, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x73, 0x12, 0x21, 0x0a, 0x0c, 0x6c, 0x69, 0x63,
	0x65, 0x6e, 0x73, 0x65, 0x5f, 0x66, 0x75, 0x6c, 0x6c, 0x18, 0x09, 0x20, 0x01, 0x28, 0x08, 0x52,
	0x0b, 0x6c, 0x69, 0x63, 0x65, 0x6e, 0x73, 0x65, 0x46, 0x75, 0x6c, 0x6c, 0x1a, 0x60, 0x0a, 0x16,
	0x4c, 0x69, 0x63, 0x65, 0x6e, 0x73, 0x65, 0x43, 0x61, 0x74, 0x65, 0x67, 0x6f, 0x72, 0x69, 0x65,
	0x73, 0x45, 0x6e, 0x74, 0x72, 0x79, 0x12, 0x10, 0x0a, 0x03, 0x6b, 0x65, 0x79, 0x18, 0x01, 0x20,
	0x01, 0x28, 0x09, 0x52, 0x03, 0x6b, 0x65, 0x79, 0x12, 0x30, 0x0a, 0x05, 0x76, 0x61, 0x6c, 0x75,
	0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x1a, 0x2e, 0x74, 0x72, 0x69, 0x76, 0x79, 0x2e,
	0x73, 0x63, 0x61, 0x6e, 0x6e, 0x65, 0x72, 0x2e, 0x76, 0x31, 0x2e, 0x4c, 0x69, 0x63, 0x65, 0x6e,
	0x73, 0x65, 0x73, 0x52, 0x05, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x3a, 0x02, 0x38, 0x01, 0x4a, 0x04,
	0x08, 0x03, 0x10, 0x04, 0x22, 0x91, 0x01, 0x0a, 0x0c, 0x53, 0x63, 0x61, 0x6e, 0x52, 0x65, 0x73,
	0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x20, 0x0a, 0x02, 0x6f, 0x73, 0x18, 0x01, 0x20, 0x01, 0x28,
	0x0b, 0x32, 0x10, 0x2e, 0x74, 0x72, 0x69, 0x76, 0x79, 0x2e, 0x63, 0x6f, 0x6d, 0x6d, 0x6f, 0x6e,
	0x2e, 0x4f, 0x53, 0x52, 0x02, 0x6f, 0x73, 0x12, 0x32, 0x0a, 0x07, 0x72, 0x65, 0x73, 0x75, 0x6c,
	0x74, 0x73, 0x18, 0x03, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x18, 0x2e, 0x74, 0x72, 0x69, 0x76, 0x79,
	0x2e, 0x73, 0x63, 0x61, 0x6e, 0x6e, 0x65, 0x72, 0x2e, 0x76, 0x31, 0x2e, 0x52, 0x65, 0x73, 0x75,
	0x6c, 0x74, 0x52, 0x07, 0x72, 0x65, 0x73, 0x75, 0x6c, 0x74, 0x73, 0x12, 0x2b, 0x0a, 0x06, 0x6c,
	0x61, 0x79, 0x65, 0x72, 0x73, 0x18, 0x04, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x13, 0x2e, 0x74, 0x72,
	0x69, 0x76, 0x79, 0x2e, 0x63, 0x6f, 0x6d, 0x6d, 0x6f, 0x6e, 0x2e, 0x4c, 0x61, 0x79, 0x65, 0x72,
	0x52, 0x06, 0x6c, 0x61, 0x79, 0x65, 0x72, 0x73, 0x22, 0xd5, 0x03, 0x0a, 0x06, 0x52, 0x65, 0x73,
	0x75, 0x6c, 0x74, 0x12, 0x16, 0x0a, 0x06, 0x74, 0x61, 0x72, 0x67, 0x65, 0x74, 0x18, 0x01, 0x20,
	0x01, 0x28, 0x09, 0x52, 0x06, 0x74, 0x61, 0x72, 0x67, 0x65, 0x74, 0x12, 0x45, 0x0a, 0x0f, 0x76,
	0x75, 0x6c, 0x6e, 0x65, 0x72, 0x61, 0x62, 0x69, 0x6c, 0x69, 0x74, 0x69, 0x65, 0x73, 0x18, 0x02,
	0x20, 0x03, 0x28, 0x0b, 0x32, 0x1b, 0x2e, 0x74, 0x72, 0x69, 0x76, 0x79, 0x2e, 0x63, 0x6f, 0x6d,
	0x6d, 0x6f, 0x6e, 0x2e, 0x56, 0x75, 0x6c, 0x6e, 0x65, 0x72, 0x61, 0x62, 0x69, 0x6c, 0x69, 0x74,
	0x79, 0x52, 0x0f, 0x76, 0x75, 0x6c, 0x6e, 0x65, 0x72, 0x61, 0x62, 0x69, 0x6c, 0x69, 0x74, 0x69,
	0x65, 0x73, 0x12, 0x54, 0x0a, 0x11, 0x6d, 0x69, 0x73, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x75,
	0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x18, 0x04, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x26, 0x2e,
	0x74, 0x72, 0x69, 0x76, 0x79, 0x2e, 0x63, 0x6f, 0x6d, 0x6d, 0x6f, 0x6e, 0x2e, 0x44, 0x65, 0x74,
	0x65, 0x63, 0x74, 0x65, 0x64, 0x4d, 0x69, 0x73, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x75, 0x72,
	0x61, 0x74, 0x69, 0x6f, 0x6e, 0x52, 0x11, 0x6d, 0x69, 0x73, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67,
	0x75, 0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x12, 0x14, 0x0a, 0x05, 0x63, 0x6c, 0x61, 0x73,
	0x73, 0x18, 0x06, 0x20, 0x01, 0x28, 0x09, 0x52, 0x05, 0x63, 0x6c, 0x61, 0x73, 0x73, 0x12, 0x12,
	0x0a, 0x04, 0x74, 0x79, 0x70, 0x65, 0x18, 0x03, 0x20, 0x01, 0x28, 0x09, 0x52, 0x04, 0x74, 0x79,
	0x70, 0x65, 0x12, 0x31, 0x0a, 0x08, 0x70, 0x61, 0x63, 0x6b, 0x61, 0x67, 0x65, 0x73, 0x18, 0x05,
	0x20, 0x03, 0x28, 0x0b, 0x32, 0x15, 0x2e, 0x74, 0x72, 0x69, 0x76, 0x79, 0x2e, 0x63, 0x6f, 0x6d,
	0x6d, 0x6f, 0x6e, 0x2e, 0x50, 0x61, 0x63, 0x6b, 0x61, 0x67, 0x65, 0x52, 0x08, 0x70, 0x61, 0x63,
	0x6b, 0x61, 0x67, 0x65, 0x73, 0x12, 0x47, 0x0a, 0x10, 0x63, 0x75, 0x73, 0x74, 0x6f, 0x6d, 0x5f,
	0x72, 0x65, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x73, 0x18, 0x07, 0x20, 0x03, 0x28, 0x0b, 0x32,
	0x1c, 0x2e, 0x74, 0x72, 0x69, 0x76, 0x79, 0x2e, 0x63, 0x6f, 0x6d, 0x6d, 0x6f, 0x6e, 0x2e, 0x43,
	0x75, 0x73, 0x74, 0x6f, 0x6d, 0x52, 0x65, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x52, 0x0f, 0x63,
	0x75, 0x73, 0x74, 0x6f, 0x6d, 0x52, 0x65, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x73, 0x12, 0x35,
	0x0a, 0x07, 0x73, 0x65, 0x63, 0x72, 0x65, 0x74, 0x73, 0x18, 0x08, 0x20, 0x03, 0x28, 0x0b, 0x32,
	0x1b, 0x2e, 0x74, 0x72, 0x69, 0x76, 0x79, 0x2e, 0x63, 0x6f, 0x6d, 0x6d, 0x6f, 0x6e, 0x2e, 0x53,
	0x65, 0x63, 0x72, 0x65, 0x74, 0x46, 0x69, 0x6e, 0x64, 0x69, 0x6e, 0x67, 0x52, 0x07, 0x73, 0x65,
	0x63, 0x72, 0x65, 0x74, 0x73, 0x12, 0x39, 0x0a, 0x08, 0x6c, 0x69, 0x63, 0x65, 0x6e, 0x73, 0x65,
	0x73, 0x18, 0x09, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x1d, 0x2e, 0x74, 0x72, 0x69, 0x76, 0x79, 0x2e,
	0x63, 0x6f, 0x6d, 0x6d, 0x6f, 0x6e, 0x2e, 0x44, 0x65, 0x74, 0x65, 0x63, 0x74, 0x65, 0x64, 0x4c,
	0x69, 0x63, 0x65, 0x6e, 0x73, 0x65, 0x52, 0x08, 0x6c, 0x69, 0x63, 0x65, 0x6e, 0x73, 0x65, 0x73,
	0x32, 0x50, 0x0a, 0x07, 0x53, 0x63, 0x61, 0x6e, 0x6e, 0x65, 0x72, 0x12, 0x45, 0x0a, 0x04, 0x53,
	0x63, 0x61, 0x6e, 0x12, 0x1d, 0x2e, 0x74, 0x72, 0x69, 0x76, 0x79, 0x2e, 0x73, 0x63, 0x61, 0x6e,
	0x6e, 0x65, 0x72, 0x2e, 0x76, 0x31, 0x2e, 0x53, 0x63, 0x61, 0x6e, 0x52, 0x65, 0x71, 0x75, 0x65,
	0x73, 0x74, 0x1a, 0x1e, 0x2e, 0x74, 0x72, 0x69, 0x76, 0x79, 0x2e, 0x73, 0x63, 0x61, 0x6e, 0x6e,
	0x65, 0x72, 0x2e, 0x76, 0x31, 0x2e, 0x53, 0x63, 0x61, 0x6e, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e,
	0x73, 0x65, 0x42, 0x33, 0x5a, 0x31, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d,
	0x2f, 0x61, 0x71, 0x75, 0x61, 0x73, 0x65, 0x63, 0x75, 0x72, 0x69, 0x74, 0x79, 0x2f, 0x74, 0x72,
	0x69, 0x76, 0x79, 0x2f, 0x72, 0x70, 0x63, 0x2f, 0x73, 0x63, 0x61, 0x6e, 0x6e, 0x65, 0x72, 0x3b,
	0x73, 0x63, 0x61, 0x6e, 0x6e, 0x65, 0x72, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_rpc_scanner_service_proto_rawDescOnce sync.Once
	file_rpc_scanner_service_proto_rawDescData = file_rpc_scanner_service_proto_rawDesc
)

func file_rpc_scanner_service_proto_rawDescGZIP() []byte {
	file_rpc_scanner_service_proto_rawDescOnce.Do(func() {
		file_rpc_scanner_service_proto_rawDescData = protoimpl.X.CompressGZIP(file_rpc_scanner_service_proto_rawDescData)
	})
	return file_rpc_scanner_service_proto_rawDescData
}

var file_rpc_scanner_service_proto_msgTypes = make([]protoimpl.MessageInfo, 6)
var file_rpc_scanner_service_proto_goTypes = []interface{}{
	(*ScanRequest)(nil),                     // 0: trivy.scanner.v1.ScanRequest
	(*Licenses)(nil),                        // 1: trivy.scanner.v1.Licenses
	(*ScanOptions)(nil),                     // 2: trivy.scanner.v1.ScanOptions
	(*ScanResponse)(nil),                    // 3: trivy.scanner.v1.ScanResponse
	(*Result)(nil),                          // 4: trivy.scanner.v1.Result
	nil,                                     // 5: trivy.scanner.v1.ScanOptions.LicenseCategoriesEntry
	(*common.OS)(nil),                       // 6: trivy.common.OS
	(*common.Layer)(nil),                    // 7: trivy.common.Layer
	(*common.Vulnerability)(nil),            // 8: trivy.common.Vulnerability
	(*common.DetectedMisconfiguration)(nil), // 9: trivy.common.DetectedMisconfiguration
	(*common.Package)(nil),                  // 10: trivy.common.Package
	(*common.CustomResource)(nil),           // 11: trivy.common.CustomResource
	(*common.SecretFinding)(nil),            // 12: trivy.common.SecretFinding
	(*common.DetectedLicense)(nil),          // 13: trivy.common.DetectedLicense
}
var file_rpc_scanner_service_proto_depIdxs = []int32{
	2,  // 0: trivy.scanner.v1.ScanRequest.options:type_name -> trivy.scanner.v1.ScanOptions
	5,  // 1: trivy.scanner.v1.ScanOptions.license_categories:type_name -> trivy.scanner.v1.ScanOptions.LicenseCategoriesEntry
	6,  // 2: trivy.scanner.v1.ScanOptions.distro:type_name -> trivy.common.OS
	6,  // 3: trivy.scanner.v1.ScanResponse.os:type_name -> trivy.common.OS
	4,  // 4: trivy.scanner.v1.ScanResponse.results:type_name -> trivy.scanner.v1.Result
	7,  // 5: trivy.scanner.v1.ScanResponse.layers:type_name -> trivy.common.Layer
	8,  // 6: trivy.scanner.v1.Result.vulnerabilities:type_name -> trivy.common.Vulnerability
	9,  // 7: trivy.scanner.v1.Result.misconfigurations:type_name -> trivy.common.DetectedMisconfiguration
	10, // 8: trivy.scanner.v1.Result.packages:type_name -> trivy.common.Package
	11, // 9: trivy.scanner.v1.Result.custom_resources:type_name -> trivy.common.CustomResource
	12, // 10: trivy.scanner.v1.Result.secrets:type_name -> trivy.common.SecretFinding
	13, // 11: trivy.scanner.v1.Result.licenses:type_name -> trivy.common.DetectedLicense
	1,  // 12: trivy.scanner.v1.ScanOptions.LicenseCategoriesEntry.value:type_name -> trivy.scanner.v1.Licenses
	0,  // 13: trivy.scanner.v1.Scanner.Scan:input_type -> trivy.scanner.v1.ScanRequest
	3,  // 14: trivy.scanner.v1.Scanner.Scan:output_type -> trivy.scanner.v1.ScanResponse
	14, // [14:15] is the sub-list for method output_type
	13, // [13:14] is the sub-list for method input_type
	13, // [13:13] is the sub-list for extension type_name
	13, // [13:13] is the sub-list for extension extendee
	0,  // [0:13] is the sub-list for field type_name
}

func init() { file_rpc_scanner_service_proto_init() }
func file_rpc_scanner_service_proto_init() {
	if File_rpc_scanner_service_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_rpc_scanner_service_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ScanRequest); i {
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
		file_rpc_scanner_service_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Licenses); i {
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
		file_rpc_scanner_service_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ScanOptions); i {
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
		file_rpc_scanner_service_proto_msgTypes[3].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ScanResponse); i {
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
		file_rpc_scanner_service_proto_msgTypes[4].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Result); i {
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
			RawDescriptor: file_rpc_scanner_service_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   6,
			NumExtensions: 0,
			NumServices:   1,
		},
		GoTypes:           file_rpc_scanner_service_proto_goTypes,
		DependencyIndexes: file_rpc_scanner_service_proto_depIdxs,
		MessageInfos:      file_rpc_scanner_service_proto_msgTypes,
	}.Build()
	File_rpc_scanner_service_proto = out.File
	file_rpc_scanner_service_proto_rawDesc = nil
	file_rpc_scanner_service_proto_goTypes = nil
	file_rpc_scanner_service_proto_depIdxs = nil
}
