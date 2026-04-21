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
