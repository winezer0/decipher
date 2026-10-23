package algo

const preparedInputBufferSize = 256

// 当前 Go 对至多 32 字节的拼接使用临时缓冲；这里只接管中等长度输入。
// 分别检查长度，避免先相加溢出后错误进入缓冲路径。
func preparedStackInput(first, second string) bool {
	return len(first) <= preparedInputBufferSize && len(second) <= preparedInputBufferSize-len(first) &&
		!(len(first) <= 32 && len(second) <= 32-len(first))
}

// 调用方已检查容量；缓冲仅属于本次验证调用。
func joinPreparedInput(buf []byte, first, second string) []byte {
	n := copy(buf, first)
	n += copy(buf[n:], second)
	return buf[:n]
}
