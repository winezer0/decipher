package cracker

import (
	"decipher/internal/algo"
	"sort"
)

func (e *Engine) RunIdentHash(hashFiles []string) []IdentResult {
	var identResults []IdentResult

	// 解析hash目标格式
	targets := ParseFilesToTargets(hashFiles)
	for _, target := range targets {
		hash := target.Hash

		var matched []string
		for _, a := range algo.GetAllAlgorithms() {
			if a.Identify(hash) {
				matched = append(matched, a.Name())
			}
		}

		if len(matched) == 0 {
			matched = []string{}
		} else {
			sort.Strings(matched)
		}

		identResult := IdentResult{
			Hash:       hash,
			AlgosNames: matched,
		}
		identResults = append(identResults, identResult)
	}
	return identResults
}
