package bpf

import (
	"github.com/cilium/ebpf"
	"github.com/pkg/errors"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags -target xdp ../../src/main.c -- -I /usr/include/x86_64-linux-gnu -I ../../src

func ReadXdpObjects(ops *ebpf.CollectionOptions) (*xdpObjects, error) {
	obj := &xdpObjects{}
	err := loadXdpObjects(obj, ops)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	// TODO: BPF log level remove hardcoding. yaml in config
	if err != nil {
		return nil, errors.WithStack(err)
	}

	return obj, nil
}
