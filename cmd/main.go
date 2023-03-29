package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"sort"

	"github.com/qsliu2017/bpflame/arch"
	"github.com/qsliu2017/bpflame/bpf"
	"github.com/qsliu2017/bpflame/flamegraph"
)

var (
	binPath string
	pid     int
	// timeout int
)

func init() {
	flag.StringVar(&binPath, "bin", "", "")
	flag.IntVar(&pid, "pid", 0, "")
	flag.Parse()
}

func main() {
	ctx, cancel := signal.NotifyContext(context.Background())
	defer cancel()
	l := log.New(os.Stderr, "", log.LstdFlags)

	probeNames, err := arch.ReadFuncSymbolNames(ctx, l, binPath)
	if err != nil {
		l.Fatal(err)
	}

	m := bpf.NewMap(probeNames)

	obj, err := bpf.Load(ctx, l)
	if err != nil {
		l.Fatal(err)
	}
	defer obj.Close()

	links, err := obj.Attach(ctx, l, binPath, m, pid)
	if err != nil {
		l.Fatal(err)
	}
	l.Printf("attached\n")
	defer links.Close()

	rd, err := obj.NewReader(10)
	if err != nil {
		l.Fatal(err)
	}
	defer rd.Close()

	events := make([]*bpf.Event, 0)
	defer func() {
		l.Printf("read rest events\n")
		// rest := rd.ReadAll(m)
		// events = append(events, rest...)
		sort.Slice(events, func(i, j int) bool { return events[i].Ts < events[j].Ts })
		stack := flamegraph.NewStack()
		for _, e := range events {
			if e.IsRet {
				stack.Pop(e.Probe, int(e.Ts))
			} else {
				stack.Push(e.Probe, int(e.Ts))
			}
		}
		fmt.Print(stack.Json())
	}()

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		e := rd.Read(m)
		if e == nil {
			return
		}
		events = append(events, e)
	}
}
