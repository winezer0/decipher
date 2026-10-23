package export

import (
	"context"
	"github.com/winezer0/decipher/internal/algo"
	"github.com/winezer0/decipher/internal/algo/md5"
	"github.com/winezer0/decipher/internal/cracker"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
	"unsafe"
)

var measureEncryptMemory = flag.Bool("enc-memory", false, "measure encryption peak working set in fresh Windows processes")

func TestEncryptMemoryProcess(t *testing.T) {
	format := os.Getenv("DECIPHER_ENC_MEMORY_FORMAT")
	if format == "" {
		return
	}
	engine := cracker.NewEngine(4, t.TempDir(), "")
	err := benchmarkEncryptOutput(engine, []string{os.Getenv("DECIPHER_ENC_MEMORY_PLAINS")}, []string{os.Getenv("DECIPHER_ENC_MEMORY_SALTS")}, []algo.Algorithm{&md5.MD5SaltPassAlgo{}}, os.Getenv("DECIPHER_ENC_MEMORY_OUTPUT"), format)
	if err != nil {
		t.Fatal(err)
	}
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
	fmt.Printf("ENC_PEAK %s %d\n", format, counters.PeakWorkingSet)
}

func TestEncryptPeakWorkingSet(t *testing.T) {
	if !*measureEncryptMemory {
		t.Skip("run explicitly with -enc-memory")
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, large := range []bool{false, true} {
		_, plains, salts, _, count := encryptFixture(t, large)
		for _, format := range []string{"csv", "json"} {
			for sample := 0; sample < 3; sample++ {
				ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
				cmd := exec.CommandContext(ctx, executable, "-test.run=^TestEncryptMemoryProcess$", "-test.v")
				path := filepath.Join(t.TempDir(), "result")
				cmd.Env = append(os.Environ(), "DECIPHER_ENC_MEMORY_FORMAT="+format, "DECIPHER_ENC_MEMORY_PLAINS="+plains[0], "DECIPHER_ENC_MEMORY_SALTS="+salts[0], "DECIPHER_ENC_MEMORY_OUTPUT="+path)
				output, err := cmd.CombinedOutput()
				cancel()
				if err != nil {
					t.Fatalf("child: %v: %s", err, output)
				}
				if !strings.Contains(string(output), "ENC_PEAK "+format+" ") {
					t.Fatalf("missing peak measurement: %s", output)
				}
				verifyEncryptOutput(t, path, format, count)
				fmt.Printf("ENC_MEMORY large=%t sample=%d %s", large, sample, output)
			}
		}
	}
}
