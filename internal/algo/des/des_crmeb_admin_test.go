package des

import (
	"testing"
)

func TestCrmebAdminAlgo_NeedAddToPredb(t *testing.T) {
	algo := &CrmebAdminAlgo{}
	if got := algo.NeedAddToPredb(); got != false {
		t.Errorf("CrmebAdminAlgo.NeedAddToPredb() = %v, want false", got)
	}
}

func TestCrmebAdminAlgo_SealAndRecover(t *testing.T) {
	algo := &CrmebAdminAlgo{}
	token, err := algo.Seal("password", "secretkey")
	if err != nil {
		t.Errorf("CrmebAdminAlgo.Seal() error = %v", err)
		return
	}

	got, err := algo.Recover(token, "secretkey", "")
	if err != nil {
		t.Errorf("CrmebAdminAlgo.Recover() error = %v", err)
		return
	}
	if got != "password" {
		t.Errorf("CrmebAdminAlgo.Recover() = %v, want password", got)
	}
}

func TestCrmebAdminAlgo_CanDecryptFormat(t *testing.T) {
	algorithm := &CrmebAdminAlgo{}
	valid, err := algorithm.Seal("hello", "secret")
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name  string
		token string
		want  bool
	}{
		{name: "complete DES blocks", token: valid, want: true},
		{name: "invalid Base64", token: "not-base64", want: false},
		{name: "partial DES block", token: "YQ==", want: false},
		{name: "empty ciphertext", token: "", want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := algorithm.CanDecryptFormat(tt.token); got != tt.want {
				t.Fatalf("CanDecryptFormat(%q) = %t, want %t", tt.token, got, tt.want)
			}
		})
	}
}

func TestCrmebAdminAlgo_Recover_UserProvided(t *testing.T) {
	algo := &CrmebAdminAlgo{}
	encrypted := "Ls34Pql552iTH1xkO+dy1OWAQx0GdmK5"
	key := "admin"
	expectedPlaintext := "Y9jmpE.7ERnid4BG"

	got, err := algo.Recover(encrypted, key, "")
	if err != nil {
		t.Errorf("CrmebAdminAlgo.Recover() error = %v", err)
		return
	}
	if got != expectedPlaintext {
		t.Errorf("CrmebAdminAlgo.Recover() = %v, want %v", got, expectedPlaintext)
	}
}
