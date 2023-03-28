package bpf

import (
	"context"
	"io"
	"log"

	"github.com/cilium/ebpf/link"
)

// Link represents the programs attached to the function hooks.
type Link struct {
	cookies map[uint64]string
	links   map[uint64]link.Link
}

func (obj *Object) Attach(ctx context.Context, log_ *log.Logger, binPath string, probeNames []string, pid int) (ln *Link, err error) {
	exe, err := link.OpenExecutable(binPath)
	if err != nil {
		return nil, err
	}

	ln = &Link{
		cookies: make(map[uint64]string, len(probeNames)*2),
		links:   make(map[uint64]link.Link, len(probeNames)*2),
	}
	var id uint64
	for i, name := range probeNames {
		if i%100 == 0 {
			log_.Printf("attaching probe %d/%d", i, len(probeNames))
		}
		{
			l, err := exe.Uprobe(name, obj.Uprobe, &link.UprobeOptions{
				PID:    pid,
				Cookie: id,
			})
			if err != nil {
				log_.Printf("cannot attach probe %s: %v", name, err)
				goto cleanup
			}
			ln.cookies[id] = name
			ln.links[id] = l
			id++
		}
		{
			l, err := exe.Uretprobe(name, obj.Uprobe, &link.UprobeOptions{
				PID:    pid,
				Cookie: id,
			})
			if err != nil {
				log_.Printf("cannot attach probe %s: %v", name, err)
				goto cleanup
			}
			ln.cookies[id] = name
			ln.links[id] = l
			id++
		}
	}

	return
cleanup:
	ln.Close()
	return nil, err
}

func (l *Link) Close() error {
	links := make([]io.Closer, 0, len(l.links))
	for _, ln := range l.links {
		links = append(links, ln)
	}
	return close(links...)
}
