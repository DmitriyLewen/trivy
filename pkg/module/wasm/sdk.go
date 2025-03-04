//go:build tinygo.wasm

package wasm

// This package is designed to be imported by WASM modules.
// TinyGo can build this package, but Go cannot.

import (
	"encoding/json"
	"fmt"
	"unsafe"

	"github.com/aquasecurity/trivy/pkg/module/api"
	"github.com/aquasecurity/trivy/pkg/module/serialize"
)

func Debug(message string) {
	message = fmt.Sprintf("Module %s: %s", module.Name(), message)
	ptr, size := stringToPtr(message)
	_debug(ptr, size)
}

func Info(message string) {
	message = fmt.Sprintf("Module %s: %s", module.Name(), message)
	ptr, size := stringToPtr(message)
	_info(ptr, size)
}

func Warn(message string) {
	message = fmt.Sprintf("Module %s: %s", module.Name(), message)
	ptr, size := stringToPtr(message)
	_warn(ptr, size)
}

func Error(message string) {
	message = fmt.Sprintf("Module %s: %s", module.Name(), message)
	ptr, size := stringToPtr(message)
	_error(ptr, size)
}

//go:wasmimport env debug
func _debug(ptr uint32, size uint32)

//go:wasmimport env info
func _info(ptr uint32, size uint32)

//go:wasmimport env warn
func _warn(ptr uint32, size uint32)

//go:wasmimport env error
func _error(ptr uint32, size uint32)

var module api.Module

func RegisterModule(p api.Module) {
	module = p
}

//go:wasmexport name
func _name() uint64 {
	name := module.Name()
	ptr, size := stringToPtr(name)
	return (uint64(ptr) << uint64(32)) | uint64(size)
}

//go:wasmexport api_version
func _apiVersion() uint32 {
	return api.Version
}

//go:wasmexport version
func _version() uint32 {
	return uint32(module.Version())
}

//go:wasmexport is_analyzer
func _isAnalyzer() uint64 {
	if _, ok := module.(api.Analyzer); !ok {
		return 0
	}
	return 1
}

//go:wasmexport required
func _required() uint64 {
	files := module.(api.Analyzer).RequiredFiles()
	ss := serialize.StringSlice(files)
	return marshal(ss)
}

//go:wasmexport analyze
func _analyze(ptr, size uint32) uint64 {
	filePath := ptrToString(ptr, size)
	custom, err := module.(api.Analyzer).Analyze(filePath)
	if err != nil {
		Error(fmt.Sprintf("analyze error: %s", err))
		return 0
	}
	return marshal(custom)
}

//go:wasmexport is_post_scanner
func _isPostScanner() uint64 {
	if _, ok := module.(api.PostScanner); !ok {
		return 0
	}
	return 1
}

//go:wasmexport post_scan_spec
func _post_scan_spec() uint64 {
	return marshal(module.(api.PostScanner).PostScanSpec())
}

//go:wasmexport post_scan
func _post_scan(ptr, size uint32) uint64 {
	var results serialize.Results
	if err := unmarshal(ptr, size, &results); err != nil {
		Error(fmt.Sprintf("post scan error: %s", err))
		return 0
	}

	results, err := module.(api.PostScanner).PostScan(results)
	if err != nil {
		Error(fmt.Sprintf("post scan error: %s", err))
		return 0
	}
	return marshal(results)
}

func marshal(v any) uint64 {
	b, err := json.Marshal(v)
	if err != nil {
		Error(fmt.Sprintf("marshal error: %s", err))
		return 0
	}

	p := uintptr(unsafe.Pointer(&b[0]))
	return (uint64(p) << uint64(32)) | uint64(len(b))
}

func unmarshal(ptr, size uint32, v any) error {
	s := ptrToString(ptr, size)
	if err := json.Unmarshal([]byte(s), v); err != nil {
		return fmt.Errorf("unmarshal error: %s", err)
	}
	return nil
}

// ptrToString returns a string from WebAssembly compatible numeric types representing its pointer and length.
func ptrToString(ptr uint32, size uint32) string {
	b := unsafe.Slice((*byte)(unsafe.Pointer(uintptr(ptr))), size)
	return *(*string)(unsafe.Pointer(&b))
}

// stringToPtr returns a pointer and size pair for the given string in a way compatible with WebAssembly numeric types.
func stringToPtr(s string) (uint32, uint32) {
	buf := []byte(s)
	ptr := &buf[0]
	unsafePtr := uintptr(unsafe.Pointer(ptr))
	return uint32(unsafePtr), uint32(len(buf))
}
