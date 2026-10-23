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

var measureSaltedCLI = flag.Bool("salted-cli-memory", false, "measure long salted dec commands in fresh processes")

func TestSaltedLongCLICommands(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, family := range []string{"md5", "sha1", "sha256"} {
		for _, order := range []string{"saltpass", "passsalt"} {
			for _, size := range []int{257, 4096} {
				t.Run(fmt.Sprintf("%s/%s/n%d", family, order, size), func(t *testing.T) {
					samples := 1
					if *measureSaltedCLI {
						samples = 3
					}
					for sample := 0; sample < samples; sample++ {
						dir := t.TempDir()
						var plains, targets, salts strings.Builder
						expected := make(map[string][]string)
						for i := 0; i < 4; i++ {
							fmt.Fprintf(&salts, "salt-%011d\n", i)
						}
						name := family + "($salt.$pass)"
						if order == "passsalt" {
							name = family + "($pass.$salt)"
						}
						for i := 0; i < 40; i++ {
							id := fmt.Sprintf("-%08d", i)
							plain := strings.Repeat("p", size-16-len(id)) + id
							fmt.Fprintln(&plains, plain)
							if i%2 != 0 {
								continue
							}
							salt := fmt.Sprintf("salt-%011d", i%4)
							password, secret := "pre-"+plain+"-post", "s:"+salt+":s"
							input := secret + password
							if order == "passsalt" {
								input = password + secret
							}
							var hash string
							switch family {
							case "md5":
								hash = fmt.Sprintf("%x", md5.Sum([]byte(input)))
							case "sha1":
								hash = fmt.Sprintf("%x", sha1.Sum([]byte(input)))
							case "sha256":
								hash = fmt.Sprintf("%x", sha256.Sum256([]byte(input)))
							}
							if i%4 == 0 {
								fmt.Fprintf(&targets, "%s:%s\n", hash, salt)
							} else {
								fmt.Fprintln(&targets, hash)
							}
							expected[hash+":"+salt] = []string{hash + ":" + salt, password, salt, name, "static"}
						}
						for name, value := range map[string]string{"plains.txt": plains.String(), "targets.txt": targets.String(), "salts.txt": salts.String()} {
							if err := os.WriteFile(filepath.Join(dir, name), []byte(value), 0600); err != nil {
								t.Fatal(err)
							}
						}
						args := []string{"dec", "-i", "file:targets.txt", "-p", "file:plains.txt", "-s", "file:salts.txt", "-a", name, "-A", "--npc", "--workers", "4", "-O", "csv", "--pp=pre-", "--ps=-post", "--sp=s:", "--ss=:s"}
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
							t.Fatalf("got %d rows want %d", len(rows), len(expected)+1)
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
						if *measureSaltedCLI {
							fmt.Printf("SALTED_CLI family=%s order=%s size=%d sample=%d elapsed_ns=%d peak=%d\n", family, order, size, sample, elapsed, peak)
						}
					}
				})
			}
		}
	}
}
