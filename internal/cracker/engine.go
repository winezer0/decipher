package cracker

import (
	"runtime"
	"sync"
)

const (
	DefaultScannerBufferSize = 64 * 1024
	MaxScannerTokenSize      = 1024 * 1024
	ProgressReportInterval   = 100000
)

type Engine struct {
	workers  int
	cacheDir string
	mu       sync.Mutex
}

func NewEngine(workers int, cacheDir string) *Engine {
	if workers <= 0 {
		workers = runtime.NumCPU()
	}
	return &Engine{
		workers:  workers,
		cacheDir: cacheDir,
	}
}
