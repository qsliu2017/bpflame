package bpf

import (
	"context"
	"io"

	"github.com/cilium/ebpf/link"
	"go.uber.org/zap"
)

// Links represents the programs attached to the function hooks.
type Links struct {
	links map[uint64]link.Link
}

func (obj *Object) Attach(ctx context.Context, logger *zap.Logger, binPath string, m *Map, pid int) (*Links, error) {
	exe, err := link.OpenExecutable(binPath)
	if err != nil {
		return nil, err
	}

	links := &Links{
		links: make(map[uint64]link.Link, m.NCookies()),
	}
	for i := 0; i < m.NCookies(); i++ {
		if i%100 == 0 {
			logger.Info("attaching probe", zap.Int("done", i), zap.Int("total", m.NCookies()))
		}
		probe, isRet := m.Get(uint64(i))
		var l link.Link
		if isRet {
			l, err = exe.Uretprobe(probe, obj.Uprobe, &link.UprobeOptions{
				PID:    pid,
				Cookie: uint64(i),
			})
		} else {
			l, err = exe.Uprobe(probe, obj.Uprobe, &link.UprobeOptions{
				PID:    pid,
				Cookie: uint64(i),
			})
		}
		if err != nil {
			logger.Error("cannot attach probe", zap.String("probe", probe), zap.Error(err))
			links.Close()
			return nil, err
		}
		links.links[uint64(i)] = l
	}

	return links, nil
}

func (l *Links) Close() error {
	links := make([]io.Closer, 0, len(l.links))
	for _, ln := range l.links {
		links = append(links, ln)
	}
	return close(links...)
}
