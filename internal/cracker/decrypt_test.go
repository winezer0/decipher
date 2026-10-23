package cracker

import (
	"encoding/base64"
	"testing"

	"github.com/winezer0/decipher/internal/algo"
	base64algo "github.com/winezer0/decipher/internal/algo/base64"
	"github.com/winezer0/decipher/internal/algo/des"
)

func TestRunDecryptValuesAcceptsSupportedFormats(t *testing.T) {
	tests := []struct {
		name      string
		algorithm algo.Algorithm
		plaintext string
		secret    string
		target    string
		secrets   []string
	}{
		{
			name:      "base64",
			algorithm: &base64algo.Base64Algo{},
			plaintext: "plain text",
			target:    base64.StdEncoding.EncodeToString([]byte("plain text")),
		},
		{
			name:      "des with valid key",
			algorithm: &des.CrmebAdminAlgo{},
			plaintext: "plain text",
			secret:    "secret",
			secrets:   []string{"wrong-key", "secret"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			target := tt.target
			if target == "" {
				var err error
				target, err = tt.algorithm.Seal(tt.plaintext, tt.secret)
				if err != nil {
					t.Fatal(err)
				}
			}
			engine := &Engine{workers: 1}
			got := engine.RunDecryptValues([]HashSaltTarget{{Hash: target}}, tt.secrets, []algo.Algorithm{tt.algorithm})
			if len(got) != 1 || got[0].Plaintext != tt.plaintext || got[0].Algorithm != tt.algorithm.Name() {
				t.Fatalf("RunDecryptValues() = %#v, want plaintext %q", got, tt.plaintext)
			}
		})
	}
}

func TestRunDecryptAppliesAffixesAndStreamsSecretsOnce(t *testing.T) {
	algorithm := &des.CrmebAdminAlgo{}
	const plaintext = "plain text"
	const secret = "candidate-key"
	const saltPrefix = "before-"
	const saltSuffix = "-after"
	target, err := algorithm.Seal(plaintext, saltPrefix+secret+saltSuffix)
	if err != nil {
		t.Fatal(err)
	}
	provider := &countedDecryptSaltProvider{values: []string{"wrong-key", secret}}
	engine := &Engine{workers: 2, SaltPrefix: saltPrefix, SaltSuffix: saltSuffix}
	targets := []HashSaltTarget{{Hash: target}, {Hash: target}}
	got := engine.runDecryptWithProviders(targets, []SaltProvider{provider}, []algo.Algorithm{algorithm})
	if provider.calls != 1 {
		t.Fatalf("provider generated %d streams, want 1", provider.calls)
	}
	if len(got) != 2 {
		t.Fatalf("got %d decrypt results, want 2", len(got))
	}
	for _, result := range got {
		if result.Plaintext != plaintext || result.Salt != secret {
			t.Errorf("unexpected result: %+v", result)
		}
	}
}

type countedDecryptSaltProvider struct {
	calls  int
	values []string
}

func (*countedDecryptSaltProvider) Name() string { return "counted" }

func (p *countedDecryptSaltProvider) Count() int64 { return int64(len(p.values)) }

func (p *countedDecryptSaltProvider) GenerateStream(stop <-chan struct{}) <-chan string {
	p.calls++
	return NewMemorySaltProvider(p.values, "counted").GenerateStream(stop)
}
