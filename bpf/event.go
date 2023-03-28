package bpf

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"os"

	"github.com/cilium/ebpf/perf"
)

type Reader struct {
	rd *perf.Reader
}

// NewReader creates a new rawEventReader with nPage pages of buffer.
func (obj *Object) NewReader(nPage int) (*Reader, error) {
	rd, err := perf.NewReader(obj.Events, nPage*os.Getpagesize())
	if err != nil {
		return nil, err
	}
	return &Reader{
		rd: rd,
	}, nil
}

type Event struct {
	Pid   uint64
	Ts    uint64
	Probe string
	IsRet bool
}

// Read reads the next event.
//
// It returns nil if the reader is closed.
func (r *Reader) Read(m *Map) *Event {
	var e *rawEvent
	for {
		e, err := r.read()
		if err != nil {
			continue
		}
		if e == nil {
			return nil
		}
		break
	}

	probe, isRet := m.Get(e.Cookie)
	return &Event{
		Pid:   e.Pid,
		Ts:    e.Ts,
		Probe: probe,
		IsRet: isRet,
	}
}

// rawEvent is the raw event format as it is passed from the BPF program to userspace.
type rawEvent struct {
	Pid    uint64
	Ts     uint64
	Cookie uint64
}

// read reads the next rawEvent.
//
// It returns nil, nil if the reader is closed.
func (r *Reader) read() (*rawEvent, error) {
	record, err := r.rd.Read()
	if err != nil {
		if errors.Is(err, perf.ErrClosed) {
			return nil, nil
		}
		return nil, err
	}

	if record.LostSamples != 0 {
		return nil, fmt.Errorf("perf event ring buffer full, dropped %d samples", record.LostSamples)
	}

	var e rawEvent
	if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &e); err != nil {
		return nil, err
	}

	return &e, nil
}

func (r *Reader) Close() error {
	return close(r.rd)
}
