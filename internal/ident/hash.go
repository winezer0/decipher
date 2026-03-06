package ident

func IsHashHexChar(c rune) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
}

func IsHashHexString(s string) bool {
	for _, c := range s {
		if !IsHashHexChar(c) {
			return false
		}
	}
	return true
}

func IsHashStringWithLen(s string, length int) bool {
	if len(s) != length {
		return false
	}
	return IsHashHexString(s)
}
