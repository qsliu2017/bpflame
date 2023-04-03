package main

import (
	"context"
	"flag"
	"fmt"
	"os/signal"
	"sort"

	"github.com/qsliu2017/bpflame/arch"
	"github.com/qsliu2017/bpflame/bpf"
	"github.com/qsliu2017/bpflame/flamegraph"
	"go.uber.org/zap"
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
	logger, _ := zap.NewDevelopment()
	defer logger.Sync()

	ctx, cancel := signal.NotifyContext(context.Background())
	defer cancel()

	probeNames, err := arch.ReadFuncSymbolNames(ctx, logger.With(zap.Namespace("arch")), binPath)
	if err != nil {
		return
	}

	m := bpf.NewMap(probeNames)

	obj, err := bpf.Load(ctx, logger.With(zap.Namespace("bpf")))
	if err != nil {
		return
	}
	defer obj.Close()

	links, err := obj.Attach(ctx, logger.With(zap.Namespace("obj")), binPath, m, pid)
	if err != nil {
		return
	}
	logger.Info("attached")
	defer links.Close()

	rd, err := obj.NewReader(10)
	if err != nil {
		logger.Error("cannot create reader", zap.Error(err))
	}
	defer rd.Close()

	events := make([]*bpf.Event, 0)
	defer func() {
		logger.Info("read rest events")
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
