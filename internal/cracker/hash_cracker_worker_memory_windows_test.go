package cracker

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"syscall"
	"testing"
	"time"
	"unsafe"
)

var measureWorkerMemory = flag.Bool("worker-memory", false, "measure cracker worker peak working set in fresh Windows processes")

func TestCrackWorkerMemoryProcess(t *testing.T) {
	name := os.Getenv("DECIPHER_WORKER_MEMORY_CASE")
	if name == "" {
		return
	}
	for _, w := range workerWorkloads {
		if w.name != name {
			continue
		}
		fixture := newWorkerFixture(t, w)
		results := fixture.run()
		fixture.check(t, results)
		var counters struct {
			Size, PageFaultCount               uint32
			PeakWorkingSet, WorkingSet         uintptr
			QuotaPeakPagedPool, QuotaPagedPool uintptr
			QuotaPeakNonPaged, QuotaNonPaged   uintptr
			Pagefile, PeakPagefile             uintptr
		}
		counters.Size = uint32(unsafe.Sizeof(counters))
		ok, _, callErr := syscall.NewLazyDLL("psapi.dll").NewProc("GetProcessMemoryInfo").Call(^uintptr(0), uintptr(unsafe.Pointer(&counters)), uintptr(counters.Size))
		if ok == 0 {
			t.Fatal(callErr)
		}
		runtime.KeepAlive(fixture)
		runtime.KeepAlive(results)
		fmt.Printf("WORKER_PEAK %s %d\n", name, counters.PeakWorkingSet)
		return
	}
	t.Fatalf("unknown workload: %s", name)
}

func TestCrackWorkerPeakWorkingSet(t *testing.T) {
	if !*measureWorkerMemory {
		t.Skip("run explicitly with -worker-memory")
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, w := range workerWorkloads {
		for sample := 0; sample < 3; sample++ {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			cmd := exec.CommandContext(ctx, executable, "-test.run=^TestCrackWorkerMemoryProcess$")
			cmd.Env = append(os.Environ(), "DECIPHER_WORKER_MEMORY_CASE="+w.name)
			output, err := cmd.CombinedOutput()
			cancel()
			if err != nil {
				t.Fatalf("child: %v %s", err, output)
			}
			var name string
			var peak uint64
			if _, err := fmt.Sscanf(string(output), "WORKER_PEAK %s %d", &name, &peak); err != nil || name != w.name || peak == 0 {
				t.Fatalf("invalid measurement: %v %s", err, output)
			}
			fmt.Printf("WORKER_MEMORY %s sample=%d peak=%d\n", name, sample, peak)
		}
	}
}
