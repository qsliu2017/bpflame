package arch

import (
	"context"
	"debug/elf"

	"go.uber.org/zap"
)

// ReadFuncSymbolNames reads the function symbols from the given binary file.
func ReadFuncSymbolNames(ctx context.Context, logger *zap.Logger, binPath string) ([]string, error) {
	f, err := elf.Open(binPath)
	if err != nil {
		logger.Error("unable to open bin file", zap.Error(err))
		return nil, err
	}
	defer f.Close()

	symbols, err := f.Symbols()
	if err != nil {
		logger.Error("unable to read symbols", zap.Error(err))
		return nil, err
	}

	names := make([]string, 0)
	for _, symbol := range symbols {
		if symbol.Info != byte(elf.STT_FUNC) {
			continue
		}
		names = append(names, symbol.Name)
	}
	logger.Debug("read function symbol names", zap.Int("n", len(names)), zap.String("path", binPath))

	return names, nil
}
