package pkg

import (
	"context"
	"debug/elf"
	"log"
)

func ReadFuncSymbolNames(ctx context.Context, l *log.Logger, binPath string) ([]string, error) {
	f, err := elf.Open(binPath)
	if err != nil {
		l.Printf("unable to open bin file: %v", err)
		return nil, err
	}
	defer f.Close()

	symbols, err := f.Symbols()
	if err != nil {
		l.Printf("unable to read symbols: %v", err)
		return nil, err
	}

	names := make([]string, 0)
	for _, symbol := range symbols {
		if symbol.Info != byte(elf.STT_FUNC) {
			continue
		}
		names = append(names, symbol.Name)
	}
	l.Printf("read %d function symbol from %s", len(names), binPath)

	return names, nil
}
