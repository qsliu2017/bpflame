package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/qsliu2017/bpflame/bpf"
	"go.uber.org/zap"
)

var (
	input  string
	output string

	pid        uint64
	ignore     string
	ignoreTime bool
)

func init() {
	flag.StringVar(&input, "input", "", "")
	flag.StringVar(&output, "output", "", "")
	flag.Uint64Var(&pid, "pid", 0, "")
	flag.StringVar(&ignore, "ignore", "", "")
	flag.BoolVar(&ignoreTime, "ignore-time", false, "")
	flag.Parse()
}

func main() {
	logger, _ := zap.NewDevelopment()

	in := os.Stdin
	if input != "" {
		f, err := os.Open(input)
		if err != nil {
			logger.Error("cannot open input file", zap.Error(err))
			return
		}
		defer f.Close()
		in = f
	}
	decoder := json.NewDecoder(in)

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

	ignoreFunc := map[string]struct{}{}
	for _, f := range strings.Split(ignore, ",") {
		ignoreFunc[f] = struct{}{}
	}

	stack := []*bpf.Event{}
	for {
		var e bpf.Event
		if err := decoder.Decode(&e); err != nil {
			break
		}
		if pid == 0 || e.Pid == pid {
			stack = append(stack, &e)
		}
	}
	sort.Slice(stack, func(i, j int) bool { return stack[i].Ts < stack[j].Ts })

	var ignoreLevel int
	probeStack := []string{}
	tsStack := []uint64{}
	for _, e := range stack {
		if e.IsRet {
			if len(probeStack) == 0 || probeStack[len(probeStack)-1] != e.Probe {
				logger.Error("probe stack is not consistent", zap.String("probe", e.Probe))
				continue
			}
			if ignoreLevel == 0 {
				duration := e.Ts - tsStack[len(tsStack)-1]
				if ignoreTime {
					duration = 1
				}
				fmt.Fprintf(out, "%s %d\n", strings.Join(probeStack, ";"), duration)
			}
			if _, ignore := ignoreFunc[e.Probe]; ignore {
				ignoreLevel--
			}
			probeStack = probeStack[:len(probeStack)-1]
			tsStack = tsStack[:len(tsStack)-1]
		} else {
			if _, ignore := ignoreFunc[e.Probe]; ignore {
				ignoreLevel++
			}
			probeStack = append(probeStack, e.Probe)
			tsStack = append(tsStack, e.Ts)
		}
	}
}
