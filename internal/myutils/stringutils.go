package myutils

import "strings"

// EqualString 判断两个字符串是否相等
// 参数:
//
//	s1: 第一个字符串
//	s2: 第二个字符串
//	ignoreCase: 是否忽略大小写(true=忽略, false=不忽略)
//
// 返回值:
//
//	bool: 两个字符串是否相等
func EqualString(s1, s2 string, ignoreCase bool) bool {
	// 如果不忽略大小写，直接使用 == 比较
	if !ignoreCase {
		return s1 == s2
	}

	// 如果忽略大小写，先将两个字符串都转为小写（或大写）再比较
	return strings.ToLower(s1) == strings.ToLower(s2)
}
