package cracker

import (
	"strings"
)

// HashSaltTarget 待解密的哈希目标
type HashSaltTarget struct {
	Hash string
	Salt string
}

// CrackerResult 解密结果
type CrackerResult struct {
	Hash      string `json:"hash"`      // 原始哈希
	AlgoType  string `json:"algo_type"` // 算法类型 (static/dynamic/encrypt)
	Algorithm string `json:"algorithm"` // 算法名称
	Plaintext string `json:"plaintext"` // 明文
	Salt      string `json:"salt"`      // 盐值
}

type IdentResult struct {
	Hash       string   `json:"hash"`
	AlgosNames []string `json:"algos_names"`
}

func (res *CrackerResult) CalcHash() string {
	lower := strings.ToLower(HashStringFormat(res.Hash))
	element := []string{lower, res.Algorithm, res.Salt, res.Plaintext}
	unique := strings.Join(element, ConcatSymbol)
	return unique
}

func LoadTargetsFromMap(raws map[string]HashSaltTarget) []HashSaltTarget {
	var news []HashSaltTarget
	for _, t := range raws {
		news = append(news, t)
	}
	return news
}

func ConvertTargetsToMap(targets []HashSaltTarget) map[string]HashSaltTarget {
	m := make(map[string]HashSaltTarget)
	for _, target := range targets {
		m[target.Hash] = target
	}
	return m
}

type HashSaltsTarget struct {
	hash  string
	salts []string
}

func ConvertToHashSaltsTarget(targets []HashSaltTarget, salts []string) []HashSaltsTarget {
	targetsWithSalts := make([]HashSaltsTarget, 0, len(targets))
	for _, target := range targets {
		if target.Salt != "" {
			targetsWithSalts = append(targetsWithSalts, HashSaltsTarget{hash: target.Hash, salts: []string{target.Salt}})
			continue
		}

		if len(salts) > 0 {
			targetsWithSalts = append(targetsWithSalts, HashSaltsTarget{hash: target.Hash, salts: salts})
			continue
		}

		targetsWithSalts = append(targetsWithSalts, HashSaltsTarget{hash: target.Hash, salts: []string{""}})
	}
	return targetsWithSalts
}
