package main

import (
	"bufio"
	"context"
	"crypto/md5"
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"
	"unsafe"
)

var measureDictionaryCLI = flag.Bool("dictionary-cli-memory", false, "measure full enc/id command time and peak working set in fresh Windows test processes")

func TestDictionaryCLIProcess(t *testing.T) {
	input := os.Getenv("DECIPHER_DICTIONARY_CLI_ARGS")
	if input == "" {
		return
	}
	var args []string
	if err := json.Unmarshal([]byte(input), &args); err != nil {
		t.Fatal(err)
	}
	output := os.Stdout
	null, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = null
	os.Args = append([]string{AppName}, args...)
	start := time.Now()
	code := run()
	elapsed := time.Since(start)
	os.Stdout = output
	if err := null.Close(); err != nil {
		t.Fatal(err)
	}
	if code != 0 {
		t.Fatalf("command exit %d", code)
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
	fmt.Printf("DICT_CLI elapsed_ns=%d peak=%d\n", elapsed.Nanoseconds(), counters.PeakWorkingSet)
}

func TestDictionaryCLIMeasurements(t *testing.T) {
	if !*measureDictionaryCLI {
		t.Skip("run explicitly with -dictionary-cli-memory")
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	const count = 10000
	for _, mode := range []string{"enc", "id"} {
		for sample := 0; sample < 3; sample++ {
			dir := t.TempDir()
			path := filepath.Join(dir, "input.txt")
			file, err := os.Create(path)
			if err != nil {
				t.Fatal(err)
			}
			writer := bufio.NewWriter(file)
			for i := 0; i < count; i++ {
				line := fmt.Sprintf("plain-%08d", i)
				if mode == "id" {
					line = fmt.Sprintf("%032x:salt", i)
				}
				if _, err := fmt.Fprintln(writer, line); err != nil {
					t.Fatal(err)
				}
			}
			if err := writer.Flush(); err != nil {
				t.Fatal(err)
			}
			if err := file.Close(); err != nil {
				t.Fatal(err)
			}
			args := []string{mode, "-O", "csv"}
			if mode == "enc" {
				args = append(args, "-p", "file:"+path, "-a", "md5($pass)", "-A", "--workers", "4")
			} else {
				args = append(args, "-i", "file:"+path)
			}
			data, err := json.Marshal(args)
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			cmd := exec.CommandContext(ctx, executable, "-test.run=^TestDictionaryCLIProcess$")
			cmd.Env = append(os.Environ(), "DECIPHER_DICTIONARY_CLI_ARGS="+string(data))
			cmd.Dir = dir
			output, err := cmd.CombinedOutput()
			cancel()
			if err != nil {
				t.Fatalf("command: %v %s", err, output)
			}
			var elapsed, peak uint64
			if _, err := fmt.Sscanf(string(output), "DICT_CLI elapsed_ns=%d peak=%d", &elapsed, &peak); err != nil || elapsed == 0 || peak == 0 {
				t.Fatalf("invalid measurement: %v %s", err, output)
			}
			validateDictionaryCLIOutput(t, filepath.Join(dir, "decipher."+mode+".csv"), mode, count)
			fmt.Printf("DICT_COMMAND mode=%s sample=%d elapsed_ns=%d peak=%d\n", mode, sample, elapsed, peak)
		}
	}
}

func validateDictionaryCLIOutput(t *testing.T, path, mode string, want int) {
	t.Helper()
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	reader := csv.NewReader(file)
	if _, err := reader.Read(); err != nil {
		t.Fatal(err)
	}
	count := 0
	seen := make(map[string]bool)
	for {
		row, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if mode == "enc" {
			if len(row) != 4 || row[0] != "md5($pass)" || row[2] != "" || row[1] != fmt.Sprintf("%x", md5.Sum([]byte(row[3]))) || seen[row[3]] {
				t.Fatalf("invalid enc row: %v", row)
			}
			seen[row[3]] = true
		} else if row[0] != fmt.Sprintf("%032x", count) {
			t.Fatalf("invalid id row: %v", row)
		}
		count++
	}
	if count != want {
		t.Fatalf("got %d rows, want %d", count, want)
	}
}
