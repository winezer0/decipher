package cracker

// Target 待解密的哈希目标
type Target struct {
	Hash string
	Salt string
}

// CrackerResult 解密结果
type CrackerResult struct {
	Hash      string `json:"hash"`      // 原始哈希
	Algorithm string `json:"algorithm"` // 算法名称
	AlgoType  string `json:"algo_type"` // 算法类型 (static/dynamic/encrypt)
	Plaintext string `json:"plaintext"` // 明文
	Salt      string `json:"salt"`      // 盐值
}
