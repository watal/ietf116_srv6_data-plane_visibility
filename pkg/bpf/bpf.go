package bpf

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -target bpf main ../../src/main.c -- -I /usr/include/x86_64-linux-gnu
