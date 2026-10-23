package export

import (
	"context"
	"github.com/winezer0/decipher/internal/cracker"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"syscall"
	"testing"
	"time"
	"unsafe"
)

var measureCacheMemory = flag.Bool("cache-memory", false, "measure cache peak working set in fresh Windows processes")

type cacheMemoryMeasurement struct {
	PeakWorkingSetBytes uintptr `json:"peak_working_set_bytes"`
	Results             int     `json:"results"`
}

func TestSuccessCacheMemoryProcess(t *testing.T) {
	input := os.Getenv("DECIPHER_CACHE_MEMORY_TARGETS")
	if input == "" {
		return
	}
	data, err := os.ReadFile(input)
	if err != nil {
		t.Fatal(err)
	}
	var targets []cracker.HashSaltTarget
	if err := json.Unmarshal(data, &targets); err != nil {
		t.Fatal(err)
	}
	data = nil
	runtime.GC()
	results := LoadSuccessCacheMap(os.Getenv("DECIPHER_CACHE_MEMORY_FILE"), targets)
	// PROCESS_MEMORY_COUNTERS: the OS retains the process lifetime peak, including
	// transient allocations. Fixtures are generated in the parent, outside this process.
	var counters struct {
		Size, PageFaultCount               uint32
		PeakWorkingSet, WorkingSet         uintptr
		QuotaPeakPagedPool, QuotaPagedPool uintptr
		QuotaPeakNonPaged, QuotaNonPaged   uintptr
		Pagefile, PeakPagefile             uintptr
	}
	counters.Size = uint32(unsafe.Sizeof(counters))
	proc := syscall.NewLazyDLL("psapi.dll").NewProc("GetProcessMemoryInfo")
	ok, _, callErr := proc.Call(^uintptr(0), uintptr(unsafe.Pointer(&counters)), uintptr(counters.Size))
	if ok == 0 {
		t.Fatal(callErr)
	}
	runtime.KeepAlive(results)
	runtime.KeepAlive(targets)
	if err := json.NewEncoder(os.Stdout).Encode(cacheMemoryMeasurement{counters.PeakWorkingSet, len(results)}); err != nil {
		t.Fatal(err)
	}
	os.Exit(0)
}

func TestSuccessCachePeakWorkingSet(t *testing.T) {
	if !*measureCacheMemory {
		t.Skip("run explicitly with -cache-memory; results include the fresh process runtime")
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, size := range successCacheWorkloads {
		t.Run(size.name(), func(t *testing.T) {
			path, targets := successCacheFixture(t, size)
			data, err := json.Marshal(targets)
			if err != nil {
				t.Fatal(err)
			}
			input := filepath.Join(t.TempDir(), "targets.json")
			if err := os.WriteFile(input, data, 0600); err != nil {
				t.Fatal(err)
			}
			for sample := 0; sample < 3; sample++ {
				ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
				cmd := exec.CommandContext(ctx, executable, "-test.run=^TestSuccessCacheMemoryProcess$")
				cmd.Env = append(os.Environ(), "DECIPHER_CACHE_MEMORY_FILE="+path, "DECIPHER_CACHE_MEMORY_TARGETS="+input)
				output, err := cmd.CombinedOutput()
				cancel()
				if err != nil {
					t.Fatalf("memory child: %v: %s", err, output)
				}
				var measured cacheMemoryMeasurement
				if err := json.Unmarshal(output, &measured); err != nil || measured.Results != size.hits || measured.PeakWorkingSetBytes == 0 {
					t.Fatalf("invalid measurement: %s, %v", output, err)
				}
				fmt.Printf("CACHE_MEMORY %s sample=%d peak_working_set_bytes=%d\n", size.name(), sample, measured.PeakWorkingSetBytes)
			}
		})
	}
}
