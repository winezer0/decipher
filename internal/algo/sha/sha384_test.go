package sha

import (
	"testing"
)

func TestSHA384Algo_Seal(t *testing.T) {
	algo := &SHA384Algo{}
	testCases := []struct {
		name      string
		plaintext string
		salt      string
		want      string
	}{
		{"123456", "123456", "", "0a989ebc4a77b56a6e2bb7b19d995d185ce44090c13e2984b7ecc6d446d4b61ea9991b76a4c2f04b1b4d244841449454"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := algo.Seal(tc.plaintext, tc.salt)
			if err != nil {
				t.Errorf("SHA384Algo.Seal() error = %v", err)
				return
			}
			if got != tc.want {
				t.Errorf("SHA384Algo.Seal() = %q, want %q", got, tc.want)
			}
		})
	}
}
