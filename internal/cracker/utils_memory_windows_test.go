package cracker

import (
	"context"
	"encoding/json"
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

var measureDictionaryMemory = flag.Bool("dictionary-memory", false, "measure dictionary input peak working set in fresh Windows processes")

func TestDictionaryMemoryProcess(t *testing.T) {
	name := os.Getenv("DECIPHER_DICTIONARY_MEMORY_CASE")
	if name == "" {
		return
	}
	var paths []string
	if err := json.Unmarshal([]byte(os.Getenv("DECIPHER_DICTIONARY_MEMORY_PATHS")), &paths); err != nil {
		t.Fatal(err)
	}
	for _, w := range dictionaryWorkloads {
		if w.name != name {
			continue
		}
		output := runDictionaryWorkload(paths, w)
		checkDictionaryOutput(t, output, w)
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
		runtime.KeepAlive(output)
		fmt.Printf("DICT_PEAK %s %d %d\n", name, counters.PeakWorkingSet, len(output.lines)+len(output.targets))
		return
	}
	t.Fatalf("unknown workload: %s", name)
}

func TestDictionaryPeakWorkingSet(t *testing.T) {
	if !*measureDictionaryMemory {
		t.Skip("run explicitly with -dictionary-memory")
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, w := range dictionaryWorkloads {
		paths := dictionaryFixture(t, w)
		data, err := json.Marshal(paths)
		if err != nil {
			t.Fatal(err)
		}
		for sample := 0; sample < 3; sample++ {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			cmd := exec.CommandContext(ctx, executable, "-test.run=^TestDictionaryMemoryProcess$")
			cmd.Env = append(os.Environ(), "DECIPHER_DICTIONARY_MEMORY_CASE="+w.name, "DECIPHER_DICTIONARY_MEMORY_PATHS="+string(data))
			output, err := cmd.CombinedOutput()
			cancel()
			if err != nil {
				t.Fatalf("child: %v %s", err, output)
			}
			var name string
			var peak uint64
			var count int
			if _, err := fmt.Sscanf(string(output), "DICT_PEAK %s %d %d", &name, &peak, &count); err != nil || name != w.name || peak == 0 || count != w.files*w.lines {
				t.Fatalf("invalid measurement: %v %s", err, output)
			}
			fmt.Printf("DICT_MEMORY %s sample=%d peak=%d count=%d\n", name, sample, peak, count)
		}
	}
}
