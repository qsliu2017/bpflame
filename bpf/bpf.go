package bpf

import (
	"bytes"
	"context"
	_ "embed"
	"io"

	"github.com/cilium/ebpf"
	"go.uber.org/zap"
)

//go:embed bpf.o
var _bpfBytes []byte

// Object is the binding of the BPF program and map.
type Object struct {
	Uprobe *ebpf.Program `ebpf:"uprobe"`
	Events *ebpf.Map     `ebpf:"events"`
}

// Load loads the BPF program and map from the embedded ELF file into the kernel.
func Load(ctx context.Context, logger *zap.Logger) (*Object, error) {

	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(_bpfBytes))
	if err != nil {
		logger.Error("cannot load spec from elf file", zap.Error(err))
		return nil, err
	}

	var obj Object
	if err := spec.LoadAndAssign(&obj, nil); err != nil {
		logger.Error("cannot load bpf obj into kernel", zap.Error(err))
		return nil, err
	}

	return &obj, nil
}

// Close closes the BPF program and map.
func (obj *Object) Close() error {
	return close(obj.Uprobe, obj.Events)
}

func close(closers ...io.Closer) error {
	var err error
	for _, c := range closers {
		if e := c.Close(); e != nil {
			err = e
		}
	}
	return err
}
