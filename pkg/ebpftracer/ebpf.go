package ebpftracer

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -type ip_key -type traffic_summary -target arm64 tracer ./c/tracer.bpf.c -- -I./c/headers -Wno-address-of-packed-member -O2 -fno-stack-protector
