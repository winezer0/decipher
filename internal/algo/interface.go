package algo

import "github.com/winezer0/decipher/internal/algo/types"

// Algorithm 定义了统一的加解密/哈希接口
type Algorithm interface {
	// Name 返回算法名称
	Name() string

	// GetAlgoType 返回算法类型，决定调用者如何处理结果
	GetAlgoType() types.AlgoType

	// NeedSalt
	// 作用：声明该算法在运行时是否需要外部 secret
	// 说明：Hash 场景下 secret 代表 Salt；Encrypt 场景下 secret 代表 Key
	// 返回: 需要则返回 true，不需要返回 false
	NeedSalt() bool

	// Seal
	// 作用：生成密文或哈希值
	// 参数说明:
	// - plaintext: 需要加密的明文
	// - secret:  (Hash的盐值) 或  (Encrypt的密钥)
	//      Static/Dynamic Hash 模式下 secret 作为 Salt (若算法内置盐则忽略)
	//  	Encrypt 模式下 secret 作为 Key (密钥)
	// 返回: token (哈希值或密文), error (仅在加密错误或系统异常时返回)
	Seal(plaintext, secret string) (string, error)

	// Recover
	// 作用：验证哈希 或 解密密文
	// 逻辑分叉：
	// 参数说明:
	// - token: 存储的哈希值或密文
	// - secret:  (Hash的盐值) 或  (Encrypt的密钥)
	// - candidatePlain: 待验证的明文 (Hash 模式必填，Encrypt 不需要明文 能解密的结果就是实际明文)
	//     1. [Encrypt]模式下 : 不传入 candidatePlain，直接使用 secret(Key) 解密 token。
	//    - 成功: 返回 (解密后的明文, nil)
	//    - 失败: 返回 ("", ErrDecryptionFailed)
	//    2. [Static/Dynamic Hash]: 使用 candidatePlain + secret 计算哈希，与 token 比对。
	//        - 成功: 返回 (candidatePlain, nil) -> 确认了明文
	//        - 失败: 返回 ("", ErrVerificationFailed)
	Recover(token, secret, candidatePlain string) (string, error)

	// NeedAddToPredb
	// 作用：判断该算法是否支持/需要预先计算缓存（pre-db）
	// 返回 true: 告诉系统"可以为我建缓存"（如 md5 这种静态 hash）
	// 返回 false: 告诉系统"不需要/不适合建缓存"（如 bcrypt 这种动态 hash，或 base64 这种编码）
	// 注意: 即使返回 false，用户仍可手动指定为 true 启用缓存功能
	NeedAddToPredb() bool

	// Identify
	// 作用：判断该token是否可能属于本算法，只有对属于本算法的字符串才应该使用本算法进行解密
	// 返回 true: 密文疑似本算法
	// 返回 false: 密文不是本算法
	Identify(token string) bool
}
