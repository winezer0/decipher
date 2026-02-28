package algo

import (
	"decipher/internal/algo/argon2"
	"decipher/internal/algo/base64"
	"decipher/internal/algo/bcrypt"
	"decipher/internal/algo/des"
	"decipher/internal/algo/md5"
	"decipher/internal/algo/mssql"
	"decipher/internal/algo/mysql"
	"decipher/internal/algo/ntlm"
	"decipher/internal/algo/phpass"
	"decipher/internal/algo/scrypt"
	"decipher/internal/algo/sha"
	"decipher/internal/algo/types"

	"github.com/winezer0/xutils/utils"
)

// GetAllAlgorithms 返回所有支持的算法实例
func GetAllAlgorithms() []Algorithm {
	return []Algorithm{
		// Encrypt Algorithms
		&base64.Base64Algo{},
		&des.CrmebAdminAlgo{},

		// Static Hash Algorithms - MD5 Series
		&md5.MD5Algo{},
		&md5.MD5MiddleAlgo{},
		&md5.MD5DoubleAlgo{},
		&md5.MD5DoubleNiuCloudAlgo{},
		&md5.MD5TripleAlgo{},
		&md5.MD5UnicodeAlgo{},
		&md5.MD5Base64Algo{},
		&md5.MD5PassSaltAlgo{},
		&md5.MD5SaltPassAlgo{},
		&md5.MD5SaltPassSaltAlgo{},
		&md5.MD5SaltMD5PassAlgo{},
		&md5.MD5MD5SaltPassAlgo{},
		&md5.MD5PassMD5SaltAlgo{},
		&md5.MD5MD5PassSaltAlgo{},
		&md5.MD5MD5SaltMD5PassAlgo{},
		&md5.MD5MD5PassMD5SaltAlgo{},
		&md5.MD5SHA1Algo{},
		&md5.MD5SubAlgo{},
		&md5.MD5LikeShop2020Algo{},
		&md5.MD5CustomMssAlgo{},
		&md5.MD5CustomNc65Algo{},
		&md5.MD5CustomGmshopAlgo{},
		&md5.MD5BTAdminAlgo{},
		// MD5 Hex Series
		&md5.MD5PassSaltHexAlgo{},
		&md5.MD5SaltPassHexAlgo{},
		&md5.MD5SaltPassSaltHexAlgo{},
		&md5.MD5SaltMD5PassHexAlgo{},
		&md5.MD5MD5SaltPassHexAlgo{},
		&md5.MD5PassMD5SaltHexAlgo{},
		&md5.MD5MD5PassSaltVBDZHexAlgo{},
		&md5.MD5MD5SaltMD5PassHexAlgo{},
		&md5.MD5MD5PassMD5SaltHexAlgo{},

		// Static Hash Algorithms - SHA Series
		&sha.SHA1Algo{},
		&sha.SHA1PassSaltAlgo{},
		&sha.SHA1SaltPassAlgo{},
		&sha.SHA1DoubleAlgo{},
		&sha.SHA1MD5Algo{},
		&sha.SHA256Algo{},
		&sha.SHA256PassSaltAlgo{},
		&sha.SHA256SaltPassAlgo{},
		&sha.SHA256MD5Algo{},
		&sha.SHA256ShiroAlgo{},
		&sha.SHA256CustomNcCloudAlgo{},
		&sha.SHA384Algo{},
		&sha.SHA512Algo{},
		&sha.SHA512PassSaltAlgo{},
		&sha.SHA512SaltPassAlgo{},
		// SHA Hex Series
		&sha.SHA1PassSaltHexAlgo{},
		&sha.SHA1SaltPassHexAlgo{},
		&sha.SHA256PassSaltHexAlgo{},
		&sha.SHA256SaltPassHexAlgo{},
		&sha.SHA512PassSaltHexAlgo{},
		&sha.SHA512SaltPassHexAlgo{},

		// Static Hash Algorithms - Database Series
		&mysql.MySQLPre41Algo{},
		&mysql.MySQL5Algo{},
		&ntlm.NTLMAlgo{},
		&mssql.MSSQL2015Algo{},

		// Dynamic Hash Algorithms
		&bcrypt.BcryptAlgo{},
		&bcrypt.BcryptMd5Algo{},
		&argon2.Argon2Algo{},
		&scrypt.ScryptAlgo{},
		&phpass.PHPassAlgo{},
	}
}

// GetStaticAlgorithms 返回所有静态哈希算法实例
func GetStaticAlgorithms() []Algorithm {
	var staticAlgos []Algorithm
	for _, alg := range GetAllAlgorithms() {
		if alg.GetAlgoType() == types.AlgoIsStatic {
			staticAlgos = append(staticAlgos, alg)
		}
	}
	return staticAlgos
}

// FilterStaticAlgorithms 从给定算法列表中过滤出静态算法
func FilterStaticAlgorithms(algos []Algorithm) []Algorithm {
	var staticAlgos []Algorithm
	for _, alg := range algos {
		if alg.GetAlgoType() == types.AlgoIsStatic {
			staticAlgos = append(staticAlgos, alg)
		}
	}
	return staticAlgos
}

// FilterDynamicAlgorithms 从给定算法列表中过滤出动态算法
func FilterDynamicAlgorithms(algos []Algorithm) []Algorithm {
	var dynamicAlgos []Algorithm
	for _, alg := range algos {
		if alg.GetAlgoType() == types.AlgoIsDynamic {
			dynamicAlgos = append(dynamicAlgos, alg)
		}
	}
	return dynamicAlgos
}

// FilterNeedsPrecomputAlgorithms 从给定算法列表中过滤出需要预计算的算法
func FilterNeedsPrecomputAlgorithms(algos []Algorithm) []Algorithm {
	var precomputAlgos []Algorithm
	for _, alg := range algos {
		if alg.NeedsPrecomputation() {
			precomputAlgos = append(precomputAlgos, alg)
		}
	}
	return precomputAlgos
}

// FilterNotNeedsPrecomputAlgorithms 从给定算法列表中过滤出不需要预计算的算法
func FilterNotNeedsPrecomputAlgorithms(algos []Algorithm) []Algorithm {
	var notPrecomputAlgos []Algorithm
	for _, alg := range algos {
		if !alg.NeedsPrecomputation() {
			notPrecomputAlgos = append(notPrecomputAlgos, alg)
		}
	}
	return notPrecomputAlgos
}

// GetDynamicAlgorithms 返回所有动态哈希算法实例
func GetDynamicAlgorithms() []Algorithm {
	var dynamicAlgos []Algorithm
	for _, alg := range GetAllAlgorithms() {
		if alg.GetAlgoType() == types.AlgoIsDynamic {
			dynamicAlgos = append(dynamicAlgos, alg)
		}
	}
	return dynamicAlgos
}

// GetDynamicAlgorithmByName 根据名称获取动态算法
func GetDynamicAlgorithmByName(name string) Algorithm {
	for _, alg := range GetAllAlgorithms() {
		if alg.GetAlgoType() == types.AlgoIsDynamic && alg.Name() == name {
			return alg
		}
	}
	return nil
}

// GetDynamicAlgorithmsByNames 根据名称列表获取动态算法
func GetDynamicAlgorithmsByNames(names []string) []Algorithm {
	var dynamicAlgos []Algorithm
	if len(names) > 0 {
		for _, name := range names {
			if dynAlg := GetDynamicAlgorithmByName(name); dynAlg != nil {
				dynamicAlgos = append(dynamicAlgos, dynAlg)
			}
		}
	} else {
		dynamicAlgos = GetDynamicAlgorithms()
	}
	return dynamicAlgos
}

// GetEncryptAlgorithms 返回所有加密算法实例
func GetEncryptAlgorithms() []Algorithm {
	var encryptAlgos []Algorithm
	for _, alg := range GetAllAlgorithms() {
		if alg.GetAlgoType() == types.AlgoIsEncrypt {
			encryptAlgos = append(encryptAlgos, alg)
		}
	}
	return encryptAlgos
}

// FilterEncryptAlgorithms 从给定算法列表中过滤出加密算法
func FilterEncryptAlgorithms(algos []Algorithm) []Algorithm {
	var encryptAlgos []Algorithm
	for _, alg := range algos {
		if alg.GetAlgoType() == types.AlgoIsEncrypt {
			encryptAlgos = append(encryptAlgos, alg)
		}
	}
	return encryptAlgos
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

// GetAlgorithmsByNames 根据名称列表获取算法
// 如果 names 为空列表或 nil，返回所有算法
func GetAlgorithmsByNames(names []string) []Algorithm {
	if len(names) == 0 {
		return GetAllAlgorithms()
	}
	var algos []Algorithm
	for _, name := range names {
		if alg := GetAlgorithmByName(name); alg != nil {
			algos = append(algos, alg)
		}
	}
	return algos
}

// GetAlgorithmNames 返回算法名称列表
func GetAlgorithmNames(algos []Algorithm) []string {
	var names []string
	for _, alg := range algos {
		names = append(names, alg.Name())
	}
	return names
}

// IsStaticAlgorithm 检查算法是否为静态哈希算法
func IsStaticAlgorithm(alg Algorithm) bool {
	return alg.GetAlgoType() == types.AlgoIsStatic
}

// IsDynamicAlgorithm 检查算法是否为动态哈希算法
func IsDynamicAlgorithm(alg Algorithm) bool {
	return alg.GetAlgoType() == types.AlgoIsDynamic
}

// IsEncryptAlgorithm 检查算法是否为加密算法
func IsEncryptAlgorithm(alg Algorithm) bool {
	return alg.GetAlgoType() == types.AlgoIsEncrypt
}

// HasAlgorithm 检查算法列表中是否包含指定名称的算法
func HasAlgorithm(algos []Algorithm, name string) bool {
	for _, alg := range algos {
		if alg.Name() == name {
			return true
		}
	}
	return false
}

// StringHasOneKey 检查字符串是否包含任意一个关键字 (从 xutils 导入的辅助函数)
// 保留此函数以兼容旧代码
func StringHasOneKey(s string, keys []string, ignoreCase bool) bool {
	return utils.StringHasOneKey(s, keys, ignoreCase)
}
