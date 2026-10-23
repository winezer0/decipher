package main

import (
	"context"
	"crypto/sha256"
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

var measurePlaintextCLI = flag.Bool("plaintext-cli-memory", false, "measure plaintext producer CLI time and peak working set in fresh processes")

func TestPlaintextCLICommands(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"short4", "short100", "short10001", "long65535", "mixed100"} {
		var lines []string
		count := 4
		switch name {
		case "short100", "mixed100":
			count = 100
		case "short10001":
			count = 10001
		case "long65535":
			count = 1
		}
		for i := 0; i < count; i++ {
			plain := fmt.Sprintf("plain-中文-%08d", i)
			if name == "long65535" || name == "mixed100" && i%2 != 0 {
				plain = strings.Repeat("x", 65535-len(plain)) + plain
			}
			lines = append(lines, plain)
		}
		for _, dynamic := range []bool{false, true} {
			name := fmt.Sprintf("%s/dynamic%t", name, dynamic)
			t.Run(name, func(t *testing.T) {
				plain := lines[len(lines)-1]
				password, salt, algorithm := "pre-"+plain+"-post", "", "sha256($pass)"
				if dynamic {
					salt, algorithm = "s1", "sha256($salt.$pass)"
				}
				hash := fmt.Sprintf("%x", sha256.Sum256([]byte(salt+password)))
				samples := 1
				if *measurePlaintextCLI {
					samples = 3
				}
				for sample := 0; sample < samples; sample++ {
					dir := t.TempDir()
					// Include blank lines, CRLF, trim whitespace and no final newline.
					input := " \r\n\t" + strings.Join(lines, " \r\n\n\t") + " "
					if err := os.WriteFile(filepath.Join(dir, "plain.txt"), []byte(input), 0600); err != nil {
						t.Fatal(err)
					}
					args := []string{"dec", "-i", hash, "-p", "file:plain.txt", "-a", algorithm, "-A", "--npc", "--workers", "4", "-O", "csv", "--pp=pre-", "--ps=-post"}
					if dynamic {
						args = append(args, "-s", "s0,s1,s2,s3")
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
						t.Fatalf("dec: %v %s", err, output)
					}
					var elapsed, peak uint64
					if _, err := fmt.Sscanf(string(output), "DICT_CLI elapsed_ns=%d peak=%d", &elapsed, &peak); err != nil || elapsed == 0 || peak == 0 {
						t.Fatalf("measurement: %v %s", err, output)
					}
					file, err := os.Open(filepath.Join(dir, "decipher.dec.csv"))
					if err != nil {
						t.Fatal(err)
					}
					rows, readErr := csv.NewReader(file).ReadAll()
					closeErr := file.Close()
					if readErr != nil || closeErr != nil {
						t.Fatalf("csv: %v %v", readErr, closeErr)
					}
					token := hash
					if salt != "" {
						token += ":" + salt
					}
					if len(rows) != 2 || !reflect.DeepEqual(rows[1], []string{token, password, salt, algorithm, "static"}) {
						t.Fatalf("incorrect output: rows=%d", len(rows))
					}
					if *measurePlaintextCLI {
						fmt.Printf("PLAINTEXT_CLI name=%s sample=%d elapsed_ns=%d peak=%d\n", name, sample, elapsed, peak)
					}
				}
			})
		}
	}
}
