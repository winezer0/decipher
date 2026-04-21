package sha

import (
	"testing"
)

func TestSHA512Algo_Seal(t *testing.T) {
	algo := &SHA512Algo{}
	testCases := []struct {
		name      string
		plaintext string
		salt      string
		want      string
	}{
		{"123456", "123456", "", "ba3253876aed6bc22d4a6ff53d8406c6ad864195ed144ab5c87621b6c233b548baeae6956df346ec8c17f5ea10f35ee3cbc514797ed7ddd3145464e2a0bab413"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := algo.Seal(tc.plaintext, tc.salt)
			if err != nil {
				t.Errorf("SHA512Algo.Seal() error = %v", err)
				return
			}
			if got != tc.want {
				t.Errorf("SHA512Algo.Seal() = %q, want %q", got, tc.want)
			}
		})
	}
}
