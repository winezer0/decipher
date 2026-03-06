package ident

func IsValidBcryptStr(token string) bool {
	// 核心：固定60长度 + 前缀是$2a$/2b$/2y$（Bcrypt的核心标识）
	if len(token) != 60 {
		return false
	}
	// 仅保留最核心的前缀校验，去掉冗余的"是否以$开头"（前缀已包含$）
	prefix := token[:4]
	return prefix == "$2a$" || prefix == "$2b$" || prefix == "$2y$"
}
