package bcrypt

import (
	"strings"
	"testing"

	"decipher/internal/algo/types"
)

func TestBcryptAlgo_Name(t *testing.T) {
	algo := &BcryptAlgo{}
	if got := algo.Name(); got != "bcrypt" {
		t.Errorf("BcryptAlgo.Name() = %v; want %v", got, "bcrypt")
	}
}

func TestBcryptAlgo_GetAlgoType(t *testing.T) {
	algo := &BcryptAlgo{}
	if got := algo.GetAlgoType(); got != types.AlgoIsDynamic {
		t.Errorf("BcryptAlgo.GetAlgoType() = %v; want %v", got, types.AlgoIsDynamic)
	}
}

func TestBcryptAlgo_NeedAddToPredb(t *testing.T) {
	algo := &BcryptAlgo{}
	if got := algo.NeedAddToPredb(); got != false {
		t.Errorf("BcryptAlgo.NeedAddToPredb() = %v; want %v", got, false)
	}
}

func TestBcryptAlgo_Seal(t *testing.T) {
	algo := &BcryptAlgo{}

	tests := []struct {
		name      string
		plaintext string
		salt      string
	}{
		{"basic", "123456", ""},
		{"empty", "", ""},
		{"with_salt", "123456", "ignored"},
		{"long_password", "this_is_a_very_long_password_that_should_work_fine", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := algo.Seal(tt.plaintext, tt.salt)
			if err != nil {
				t.Errorf("BcryptAlgo.Seal() error = %v", err)
				return
			}
			if got == "" {
				t.Error("BcryptAlgo.Seal() returned empty hash")
			}
			if !strings.HasPrefix(got, "$2a$") && !strings.HasPrefix(got, "$2b$") {
				t.Errorf("BcryptAlgo.Seal() returned invalid bcrypt hash format: %q", got)
			}
		})
	}
}

func TestBcryptAlgo_Recover(t *testing.T) {
	algo := &BcryptAlgo{}

	tests := []struct {
		name           string
		plaintext      string
		candidatePlain string
		wantMatch      bool
	}{
		{"match", "123456", "123456", true},
		{"no_match", "123456", "wrong", false},
		{"empty_match", "", "", true},
		{"long_password", "this_is_a_very_long_password", "this_is_a_very_long_password", true},
		{"long_password_no_match", "this_is_a_very_long_password", "this_is_different", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token, err := algo.Seal(tt.plaintext, "")
			if err != nil {
				t.Errorf("BcryptAlgo.Seal() error = %v", err)
				return
			}

			got, err := algo.Recover(token, "", tt.candidatePlain)

			if tt.wantMatch {
				if err != nil {
					t.Errorf("BcryptAlgo.Recover() error = %v, want nil", err)
					return
				}
				if got != tt.candidatePlain {
					t.Errorf("BcryptAlgo.Recover() = %q; want %q", got, tt.candidatePlain)
				}
			} else {
				if err != types.ErrVerificationFailed {
					t.Errorf("BcryptAlgo.Recover() error = %v; want ErrVerificationFailed", err)
				}
			}
		})
	}
}

func TestBcryptAlgo_Recover_UserProvided(t *testing.T) {
	algo := &BcryptAlgo{}

	// 测试使用用户提供的数据
	plaintext := "123456"
	salt := "666666"
	expectedToken := "$2a$10$pWBCwnGFwBt/1mq0r8GZRueBOXlI.jLHa3LyQsRC4W.7Pm2VyNuy6"

	// 测试Recover函数
	got, err := algo.Recover(expectedToken, salt, plaintext)
	if err != nil {
		t.Errorf("BcryptAlgo.Recover() error = %v", err)
		return
	}
	if got != plaintext {
		t.Errorf("BcryptAlgo.Recover() = %v, want %v", got, plaintext)
	}
}

func TestBcryptAlgo_Recover_InvalidHash(t *testing.T) {
	algo := &BcryptAlgo{}

	tests := []struct {
		name    string
		token   string
		plain   string
		wantErr bool
	}{
		{"invalid_hash", "invalid_hash", "123456", true},
		{"empty_hash", "", "123456", true},
		{"short_hash", "$2a$10$", "123456", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := algo.Recover(tt.token, "", tt.plain)
			if (err != nil) != tt.wantErr {
				t.Errorf("BcryptAlgo.Recover() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
