package sha

import (
	"testing"

	"github.com/winezer0/decipher/internal/algo/types"
)

func TestSHA256CustomNcCloudAlgo_GetAlgoType(t *testing.T) {
	algo := &SHA256CustomNcCloudAlgo{}
	if got := algo.GetAlgoType(); got != types.AlgoIsStatic {
		t.Errorf("SHA256CustomNcCloudAlgo.GetAlgoType() = %v, want AlgoIsStatic", got)
	}
}

func TestSHA256CustomNcCloudAlgo_Seal(t *testing.T) {
	algo := &SHA256CustomNcCloudAlgo{}
	testCases := []struct {
		name      string
		plaintext string
		salt      string
		want      string
	}{
		{"123456", "123456", "", "S_S++jZae727K08KaOmKSgOaGzww/XVqGr/PKEgIMkjrcbJI="},
		{"empty", "", "", "S_S++47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU="},
		{"user-provided", "1qaz2wsx", "1001V11000000033Z1AA", "S_S++Omg71yFK7mPaonACCrzlqiN9XDS7conOCz+34aKmwV4="},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := algo.Seal(tc.plaintext, tc.salt)
			if err != nil {
				t.Errorf("SHA256CustomNcCloudAlgo.Seal() error = %v", err)
				return
			}
			if got != tc.want {
				t.Errorf("SHA256CustomNcCloudAlgo.Seal(%q, %q) = %q, want %q", tc.plaintext, tc.salt, got, tc.want)
			}
		})
	}
}

func TestSHA256CustomNcCloudAlgo_Recover(t *testing.T) {
	algo := &SHA256CustomNcCloudAlgo{}

	// Test with 123456
	plaintext := "123456"
	salt := ""
	token, _ := algo.Seal(plaintext, salt)

	// Test with user-provided data
	userPlaintext := "1qaz2wsx"
	userSalt := "1001V11000000033Z1AA"
	userToken := "S_S++Omg71yFK7mPaonACCrzlqiN9XDS7conOCz+34aKmwV4="

	testCases := []struct {
		name           string
		token          string
		salt           string
		candidatePlain string
		expected       string
		expectedErr    bool
	}{
		{"success-123456", token, salt, plaintext, plaintext, false},
		{"failure-123456", token, salt, "wrong", "", true},
		{"success-user-provided", userToken, userSalt, userPlaintext, userPlaintext, false},
		{"failure-user-provided", userToken, userSalt, "wrong", "", true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := algo.Recover(tc.token, tc.salt, tc.candidatePlain)
			if tc.expectedErr {
				if err != types.ErrVerificationFailed {
					t.Errorf("SHA256CustomNcCloudAlgo.Recover() error = %v, want ErrVerificationFailed", err)
				}
				if got != "" {
					t.Errorf("SHA256CustomNcCloudAlgo.Recover() = %q, want 空字符串", got)
				}
			} else {
				if err != nil {
					t.Errorf("SHA256CustomNcCloudAlgo.Recover() error = %v, want nil", err)
					return
				}
				if got != tc.expected {
					t.Errorf("SHA256CustomNcCloudAlgo.Recover() = %q, want %q", got, tc.expected)
				}
			}
		})
	}
}
