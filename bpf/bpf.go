package bpf

import (
	"bytes"
	"context"
	_ "embed"
	"io"
	"log"

	"github.com/cilium/ebpf"
)

// Object is the binding of the BPF program and map.
type Object struct {
	Uprobe *ebpf.Program `ebpf:"uprobe"`
	Events *ebpf.Map     `ebpf:"events"`
}

// Load loads the BPF program and map from the embedded ELF file into the kernel.
func Load(ctx context.Context, l *log.Logger) (*Object, error) {
	//go:embed bpf.o
	var _bpfBytes []byte

	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(_bpfBytes))
	if err != nil {
		l.Printf("cannot load spec from elf file: %v", err)
		return nil, err
	}

	var obj Object
	if err := spec.LoadAndAssign(&obj, nil); err != nil {
		l.Printf("cannot load bpf obj into kernel: %v", err)
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
