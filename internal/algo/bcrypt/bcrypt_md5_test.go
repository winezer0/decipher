package bcrypt

import (
	"github.com/winezer0/decipher/internal/algo/types"
	"testing"
)

func TestBcryptMd5Algo(t *testing.T) {
	algo := &BcryptMd5Algo{}

	// Test Name
	if got := algo.Name(); got != "bcrypt(md5($pass))" {
		t.Errorf("Name() = %q; want %q", got, "bcrypt(md5($pass))")
	}

	// Test GetAlgoType
	if got := algo.GetAlgoType(); got != types.AlgoIsDynamic {
		t.Errorf("GetAlgoType() = %v; want %v", got, types.AlgoIsDynamic)
	}

	// Test NeedAddToPredb
	if got := algo.NeedAddToPredb(); got != false {
		t.Errorf("NeedAddToPredb() = %v; want %v", got, false)
	}

	// Test Seal and Recover with non-empty plaintext
	plaintext := "test123"
	sealed, err := algo.Seal(plaintext, "")
	if err != nil {
		t.Errorf("Seal() error = %v; want nil", err)
	}

	recovered, err := algo.Recover(sealed, "", plaintext)
	if err != nil {
		t.Errorf("Recover() error = %v; want nil", err)
	}
	if recovered != plaintext {
		t.Errorf("Recover() = %q; want %q", recovered, plaintext)
	}

	// Test Recover with wrong candidate
	wrongPlaintext := "wrong123"
	_, err = algo.Recover(sealed, "", wrongPlaintext)
	if err == nil {
		t.Errorf("Recover() with wrong candidate should return error")
	}

	// Test Seal and Recover with empty string
	emptyPlaintext := ""
	emptySealed, err := algo.Seal(emptyPlaintext, "")
	if err != nil {
		t.Errorf("Seal() with empty string error = %v; want nil", err)
	}

	emptyRecovered, err := algo.Recover(emptySealed, "", emptyPlaintext)
	if err != nil {
		t.Errorf("Recover() with empty string error = %v; want nil", err)
	}
	if emptyRecovered != emptyPlaintext {
		t.Errorf("Recover() with empty string = %q; want %q", emptyRecovered, emptyPlaintext)
	}
}

func TestBcryptMd5Algo_Recover_UserProvided(t *testing.T) {
	algo := &BcryptMd5Algo{}

	// 测试使用用户提供的数据
	plaintext := "123456"
	salt := "666666"
	expectedToken := "$2a$10$XXQ9T37nj8Jz71bC2lXc8OT5fOiNINs/fL0XKpgS8d5a6VftmJnI6"

	// 测试Recover函数
	got, err := algo.Recover(expectedToken, salt, plaintext)
	if err != nil {
		t.Errorf("BcryptMd5Algo.Recover() error = %v", err)
		return
	}
	if got != plaintext {
		t.Errorf("BcryptMd5Algo.Recover() = %v, want %v", got, plaintext)
	}
}
