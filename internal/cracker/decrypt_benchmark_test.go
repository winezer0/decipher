package cracker

import (
	"fmt"
	"testing"

	"github.com/winezer0/decipher/internal/algo"
	"github.com/winezer0/decipher/internal/algo/des"
	logging "github.com/winezer0/zaplogs"
)

func BenchmarkDecryptDispatch(b *testing.B) {
	if err := logging.InitDefaultLogger(logging.LogConfig{Level: "error", ConsoleFormat: "LCM"}); err != nil {
		b.Fatal(err)
	}

	desAlgorithm := &des.CrmebAdminAlgo{}
	validCiphertext, err := desAlgorithm.Seal("benchmark plaintext", "secret-0")
	if err != nil {
		b.Fatal(err)
	}
	for _, scenario := range []struct {
		name  string
		token string
		found bool
	}{
		{name: "malformed", token: "not-base64"},
		{name: "valid-des", token: validCiphertext, found: true},
	} {
		for _, secretCount := range []int{1, 1000} {
			b.Run(fmt.Sprintf("%s/secrets-%d", scenario.name, secretCount), func(b *testing.B) {
				secrets := make([]string, secretCount)
				for i := range secrets {
					secrets[i] = fmt.Sprintf("secret-%d", i)
				}
				engine := &Engine{workers: 4}
				targets := []HashSaltTarget{{Hash: scenario.token}}
				algorithms := algo.FilterEncryptAlgorithms(algo.GetAllAlgorithms())

				b.ReportAllocs()
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					results := engine.RunDecryptValues(targets, secrets, algorithms)
					if (len(results) > 0) != scenario.found {
						b.Fatalf("unexpected decrypt result: %+v", results)
					}
				}
			})
		}
	}
}

func BenchmarkDecryptAffixExpansion(b *testing.B) {
	if err := logging.InitDefaultLogger(logging.LogConfig{Level: "error", ConsoleFormat: "LCM"}); err != nil {
		b.Fatal(err)
	}

	algorithm := &des.CrmebAdminAlgo{}
	ciphertext, err := algorithm.Seal("benchmark plaintext", "target-key")
	if err != nil {
		b.Fatal(err)
	}
	targets := make([]HashSaltTarget, 32)
	for i := range targets {
		targets[i] = HashSaltTarget{Hash: ciphertext}
	}
	secrets := make([]string, 256)
	for i := range secrets {
		secrets[i] = fmt.Sprintf("candidate-key-%d", i)
	}

	for _, affix := range []bool{false, true} {
		b.Run(fmt.Sprintf("affix-%t", affix), func(b *testing.B) {
			engine := &Engine{workers: 4}
			if affix {
				engine.SaltPrefix = "prefix-"
				engine.SaltSuffix = "-suffix"
			}
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				engine.RunDecryptValues(targets, secrets, []algo.Algorithm{algorithm})
			}
		})
	}
}

func BenchmarkEncryptAffixExpansion(b *testing.B) {
	if err := logging.InitDefaultLogger(logging.LogConfig{Level: "error", ConsoleFormat: "LCM"}); err != nil {
		b.Fatal(err)
	}

	plaintexts := make([]string, 32)
	for i := range plaintexts {
		plaintexts[i] = fmt.Sprintf("plaintext-%d", i)
	}
	secrets := make([]string, 256)
	for i := range secrets {
		secrets[i] = fmt.Sprintf("candidate-key-%d", i)
	}
	algorithm := &des.CrmebAdminAlgo{}
	for _, affix := range []bool{false, true} {
		b.Run(fmt.Sprintf("affix-%t", affix), func(b *testing.B) {
			engine := &Engine{workers: 4}
			if affix {
				engine.PassPrefix = "pass-prefix-"
				engine.PassSuffix = "-pass-suffix"
				engine.SaltPrefix = "salt-prefix-"
				engine.SaltSuffix = "-salt-suffix"
			}
			emit := func(EncryptResult) error { return nil }
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if err := engine.RunEncryptValuesStream(plaintexts, secrets, []algo.Algorithm{algorithm}, emit); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
