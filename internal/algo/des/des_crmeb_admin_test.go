package des

import (
	"testing"
)

func TestCrmebAdminAlgo_Name(t *testing.T) {
	algo := &CrmebAdminAlgo{}
	if got := algo.Name(); got != "des_crmeb_admin" {
		t.Errorf("CrmebAdminAlgo.Name() = %v, want des_crmeb_admin", got)
	}
}

func TestCrmebAdminAlgo_NeedsPrecomputation(t *testing.T) {
	algo := &CrmebAdminAlgo{}
	if got := algo.NeedsPrecomputation(); got != false {
		t.Errorf("CrmebAdminAlgo.NeedsPrecomputation() = %v, want false", got)
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
