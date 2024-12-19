//go:generate protoc --proto_path=../proto --go_out=../api --go_opt=paths=source_relative --go_opt=default_api_level=API_HYBRID --go_opt=Minterop.proto=github.com/pyroscope-io/dotnetdiag/examples/attach-profiler/api interop.proto

package api
