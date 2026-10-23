package main

import (
	"context"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

var measureSaltPipelineCLI = flag.Bool("salt-pipeline-cli-memory", false, "measure real dec command time and peak working set in fresh processes")

func TestSaltPipelineCLICommands(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, source := range []string{"file", "memory", "generator"} {
		for _, family := range []string{"md5", "sha1", "sha256"} {
			for _, affix := range []bool{false, true} {
				samples := 1
				if *measureSaltPipelineCLI {
					samples = 3
				}
				for sample := 0; sample < samples; sample++ {
					dir := t.TempDir()
					var plains, targets strings.Builder
					expected := make(map[string][]string)
					for i := 0; i < 200; i++ {
						plain := fmt.Sprintf("worker-plain-%08d", i)
						fmt.Fprintln(&plains, plain)
						if i%2 != 0 {
							continue
						}
						salt := fmt.Sprintf("s%d", i%4)
						password, secret := plain, salt
						if affix {
							password = "pre-" + plain + "-post"
							secret = "s-pre-" + salt + "-s-post"
						}
						var hash string
						if family == "md5" {
							hash = fmt.Sprintf("%x", md5.Sum([]byte(secret+password)))
						} else if family == "sha1" {
							hash = fmt.Sprintf("%x", sha1.Sum([]byte(secret+password)))
						} else {
							hash = fmt.Sprintf("%x", sha256.Sum256([]byte(secret+password)))
						}
						if i%4 == 0 {
							fmt.Fprintf(&targets, "%s:%s\n", hash, salt)
						} else {
							fmt.Fprintln(&targets, hash)
						}
						expected[hash+":"+salt] = []string{hash + ":" + salt, password, salt, family + "($salt.$pass)", "static"}
					}
					for name, value := range map[string]string{"plains.txt": plains.String(), "targets.txt": targets.String(), "salts.txt": "s0\ns1\ns2\ns3\n"} {
						if err := os.WriteFile(filepath.Join(dir, name), []byte(value), 0600); err != nil {
							t.Fatal(err)
						}
					}
					args := []string{"dec", "-i", "file:targets.txt", "-p", "file:plains.txt", "-s", "file:salts.txt", "-a", family + "($pass)," + family + "($salt.$pass)," + family + "($pass.$salt)", "-A", "--npc", "--workers", "4", "-O", "csv"}
					if affix {
						args = append(args, "--pp=pre-", "--ps=-post", "--sp=s-pre-", "--ss=-s-post")
					}
					for i, arg := range args {
						if arg == "file:salts.txt" {
							switch source {
							case "memory":
								args[i] = "s0,s1,s2,s3"
							case "generator":
								args[i] = "gen:2:s0123"
							}
						}
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
						t.Fatalf("CSV: %v %v", readErr, closeErr)
					}
					if len(rows) != len(expected)+1 {
						t.Fatalf("got %d rows, want %d", len(rows), len(expected)+1)
					}
					seen := make(map[string]bool)
					for _, row := range rows[1:] {
						if len(row) != 5 {
							t.Fatalf("invalid row: %v", row)
						}
						want, ok := expected[row[0]]
						if !ok || seen[row[0]] || strings.Join(row, "\x00") != strings.Join(want, "\x00") {
							t.Fatalf("unexpected result: %v", row)
						}
						seen[row[0]] = true
					}
					if *measureSaltPipelineCLI {
						fmt.Printf("PIPELINE_CLI source=%s family=%s affix=%t sample=%d elapsed_ns=%d peak=%d\n", source, family, affix, sample, elapsed, peak)
					}
				}
			}
		}
	}
}
