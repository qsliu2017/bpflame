package main

import (
	"context"
	"encoding/json"
	"flag"
	"os"
	"os/signal"

	"github.com/qsliu2017/bpflame/arch"
	"github.com/qsliu2017/bpflame/bpf"
	"go.uber.org/zap"
)

var (
	binPath string
	pid     int
	output  string
)

func init() {
	flag.StringVar(&binPath, "bin", "", "")
	flag.IntVar(&pid, "pid", 0, "")
	flag.StringVar(&output, "output", "", "")
	flag.Parse()
}

func main() {
	logger, _ := zap.NewDevelopment()
	defer logger.Sync()

	out := os.Stdout
	if output != "" {
		f, err := os.Create(output)
		if err != nil {
			logger.Error("cannot create output file", zap.Error(err))
			return
		}
		defer f.Close()
		out = f
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, os.Kill)
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
	logger.Debug("attached")
	defer links.Close()

	rd, err := obj.NewReader(10, logger.With(zap.Namespace("perf_reader")))
	if err != nil {
		logger.Error("cannot create reader", zap.Error(err))
	}
	defer rd.Close()

	encoder := json.NewEncoder(out)
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
		encoder.Encode(e)
	}
}
