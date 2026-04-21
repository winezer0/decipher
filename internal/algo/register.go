package algo

import (
	"decipher/internal/algo/base64"
	"decipher/internal/algo/bcrypt"
	"decipher/internal/algo/des"
	"decipher/internal/algo/md5"
	"decipher/internal/algo/mssql"
	"decipher/internal/algo/mysql"
	"decipher/internal/algo/ntlm"
	"decipher/internal/algo/scrypt"
	"decipher/internal/algo/sha"
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
		&md5.MD5LikeShop2021Algo{},
		&md5.MD5CustomMssAlgo{},
		&md5.MD5CustomNc65Algo{},
		&md5.MD5CustomGmshopAlgo{},
		&md5.MD5PassSaltAlgo2{},
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
		&sha.SHA1PassSalt2Algo{},
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
		&bcrypt.BcryptPassSaltAlgo{},
		&scrypt.ScryptAlgo{},
	}
}
