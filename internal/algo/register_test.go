package algo

import "testing"

func TestGetAlgorithmByName_CustomAlgorithmsRegistered(t *testing.T) {
	if got := GetAlgorithmByName("sha1_custom_yyk"); got == nil {
		t.Fatalf("GetAlgorithmByName(sha1_custom_yyk) = nil, want non-nil")
	}
	if got := GetAlgorithmByName("md5_custom_lizhi"); got == nil {
		t.Fatalf("GetAlgorithmByName(md5_custom_lizhi) = nil, want non-nil")
	}
}
