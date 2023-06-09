package bpf

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"

	"github.com/cilium/ebpf/perf"
	"go.uber.org/zap"
)

type Reader struct {
	rd     *perf.Reader
	logger *zap.Logger
}

// NewReader creates a new rawEventReader with nPage pages of buffer.
func (obj *Object) NewReader(nPage int, logger *zap.Logger) (*Reader, error) {
	rd, err := perf.NewReader(obj.Events, nPage*os.Getpagesize())
	if err != nil {
		logger.Error("cannot create perf reader", zap.Error(err))
		return nil, err
	}
	return &Reader{
		rd:     rd,
		logger: logger,
	}, nil
}

type Event struct {
	Pid   int    `json:"pid"`
	Tgid  int    `json:"tgid"`
	Ts    uint64 `json:"ts"`
	Probe string `json:"probe"`
	IsRet bool   `json:"is_ret"`
}

// Read reads the next event.
//
// It returns nil if the reader is closed.
func (r *Reader) Read(m Map) (*Event, error) {
	e, err := r.read()
	if err != nil {
		return nil, err
	}
	if e == nil {
		return nil, nil
	}

	probe, isRet := m.Get(e.Cookie)
	return &Event{
		Pid:   int(e.PidTgid & ((1 << 32) - 1)),
		Tgid:  int(e.PidTgid >> 32),
		Ts:    e.Ts,
		Probe: probe,
		IsRet: isRet,
	}, nil
}

// rawEvent is the raw event format as it is passed from the BPF program to userspace.
type rawEvent struct {
	PidTgid uint64
	Ts      uint64
	Cookie  uint64
}

// read reads the next rawEvent.
//
// It returns nil, nil if the reader is closed.
func (r *Reader) read() (*rawEvent, error) {
	record, err := r.rd.Read()
	r.logger.Debug("read perf record", zap.Error(err), zap.Any("record", record))
	if err != nil {
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
	return r.rd.Close()
}
