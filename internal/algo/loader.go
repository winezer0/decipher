package algo

import (
	"decipher/internal/algo/types"
	"github.com/winezer0/xutils/utils"
)

// FilterNeedAddToPredbAlogs 从给定算法列表中过滤出需要预计算的算法
func FilterNeedAddToPredbAlogs(algos []Algorithm) []Algorithm {
	var filter []Algorithm
	for _, alg := range algos {
		if alg.NeedAddToPredb() {
			filter = append(filter, alg)
		}
	}
	return filter
}

// FilterNotNeedAddToPredbAlogs 从给定算法列表中过滤出不需要预计算的算法
func FilterNotNeedAddToPredbAlogs(algos []Algorithm) []Algorithm {
	var filter []Algorithm
	for _, alg := range algos {
		if !alg.NeedAddToPredb() {
			filter = append(filter, alg)
		}
	}
	return filter
}

// FilterStaticAlgorithms 从给定算法列表中过滤出静态算法
func FilterStaticAlgorithms(algos []Algorithm) []Algorithm {
	var filter []Algorithm
	for _, alg := range algos {
		if alg.GetAlgoType() == types.AlgoIsStatic {
			filter = append(filter, alg)
		}
	}
	return filter
}

// FilterDynamicAlgorithms 从给定算法列表中过滤出动态算法
func FilterDynamicAlgorithms(algos []Algorithm) []Algorithm {
	var filter []Algorithm
	for _, alg := range algos {
		if alg.GetAlgoType() == types.AlgoIsDynamic {
			filter = append(filter, alg)
		}
	}
	return filter
}

// FilterEncryptAlgorithms 从给定算法列表中过滤出加密算法
func FilterEncryptAlgorithms(algos []Algorithm) []Algorithm {
	var filter []Algorithm
	for _, alg := range algos {
		if alg.GetAlgoType() == types.AlgoIsEncrypt {
			filter = append(filter, alg)
		}
	}
	return filter
}

// GetAlgorithmByName 根据名称获取算法
func GetAlgorithmByName(name string) Algorithm {
	for _, alg := range GetAllAlgorithms() {
		if alg.Name() == name {
			return alg
		}
	}
	return nil
}

// GetAlgorithmNames 返回算法名称列表
func GetAlgorithmNames(algos []Algorithm) []string {
	var names []string
	for _, alg := range algos {
		names = append(names, alg.Name())
	}
	return names
}

// GetAlgorithmsByKeys 根据关键字列表获取算法（支持部分匹配）
// 使用 utils.StringHasOneKey 检查算法名称是否包含任意一个关键字
// 如果 keys 为空列表或 nil，返回所有算法
// ignoreCase 为 true 时忽略大小写匹配
func GetAlgorithmsByKeys(keys []string, precise bool) []Algorithm {
	if len(keys) == 0 {
		return GetAllAlgorithms()
	}
	var algos []Algorithm
	for _, alg := range GetAllAlgorithms() {
		if precise {
			if utils.StringInStrings(alg.Name(), keys, true) {
				algos = append(algos, alg)
			}
		} else {
			if utils.StringHasOneKey(alg.Name(), keys, true) {
				algos = append(algos, alg)
			}
		}
	}
	return algos
}
