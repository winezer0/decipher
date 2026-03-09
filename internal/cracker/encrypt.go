package cracker

import (
	"decipher/internal/algo"
	"strings"
	"sync"

	"github.com/winezer0/xutils/logging"
)

// RunEncrypt 对文本和盐值进行加密，并返回加密结果列表
// 输出格式: Algorithm:hash:salt:plaintext
func (e *Engine) RunEncrypt(plainDicts []string, secretDicts []string, algos []algo.Algorithm) []string {
	// 加载文件到列表
	texts := ReadFilesToStrings(plainDicts, false)

	// 使用 SaltProvider 支持生成器
	var saltProvider SaltProvider
	providers := InitSaltProviders(secretDicts)
	if len(providers) == 0 {
		logging.Warnf("InitSaltProviders returned empty list, using empty salt")
		saltProvider = NewMemorySaltProvider([]string{""}, "empty")
	} else {
		saltProvider = NewMultiSaltProvider(providers)
	}

	logging.Infof("Loaded %d text(s) to encrypt", len(texts))
	// logging.Infof("Loaded %d salt(s) to use", len(secrets)) // 无法预知总数

	type job struct {
		text string
		salt string
		alg  algo.Algorithm
	}

	jobs := make(chan job, e.workers*2)
	resultsChan := make(chan string, e.workers*10)
	var wg sync.WaitGroup

	// Start workers
	for i := 0; i < e.workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobs {
				hash, err := j.alg.Seal(e.AffixPasswd(j.text), e.AffixSalt(j.salt))
				if err != nil {
					// 加密失败，跳过此任务
					continue
				}
				// 输出格式：Algorithm:hash:salt:plaintext
				element := []string{j.alg.Name(), hash, j.salt, j.text}
				// 使用 strings.Join 可能会有问题如果 salt 或 text 包含分隔符
				// 这里简单处理
				resultsChan <- strings.Join(element, ConcatSymbol)
			}
		}()
	}

	// Producer
	go func() {
		defer close(jobs)

		// 简单的流式处理：对每个算法，每个文本，遍历一次 Salt 流
		// 如果文本很多，Salt 流很大，这里会很慢。
		// 但 Encrypt 模式通常用于测试或生成数据，量级可能不如 Crack 模式大。
		// 仍然建议分批处理。

		// 缓存一部分 Salt 以减少生成开销？
		// 或者直接流式遍历。

		// 这里的逻辑：
		// 遍历算法 -> 遍历文本 -> 遍历 Salt
		// 为了复用 Salt 流，我们可以把算法和文本放在内层？
		// 遍历 Salt -> 遍历算法 -> 遍历文本
		// 这样只需要生成一次 Salt 流。
		// 但是 SaltProvider 可能无限？(e.g. random count very large)
		// 无论如何都要遍历完 Salt。

		// 优化：一次性读取所有文本（假设不大），然后流式读取 Salt，对每个 Salt，生成 (Alg, Text) 组合。
		// 但是如果有些算法不需要 Salt，就不应该遍历 Salt 流。

		// 分离需要 Salt 和不需要 Salt 的算法
		var needSaltAlgos []algo.Algorithm
		var noSaltAlgos []algo.Algorithm
		for _, a := range algos {
			if a.NeedSalt() {
				needSaltAlgos = append(needSaltAlgos, a)
			} else {
				noSaltAlgos = append(noSaltAlgos, a)
			}
		}

		// 1. 处理不需要 Salt 的算法
		for _, alg := range noSaltAlgos {
			for _, text := range texts {
				jobs <- job{text: text, salt: "", alg: alg}
			}
		}

		// 2. 处理需要 Salt 的算法
		if len(needSaltAlgos) > 0 {
			// 如果没有提供 Salt，使用空 Salt (与测试行为一致)
			// 测试 "Single text, no salt" 期望 md5($salt.$pass) 在无 salt 时运行一次
			// 如果 saltProvider 是空的 (initSaltProviders 返回 empty list)，它已经被设置为 NewMemorySaltProvider([]string{""})
			// 所以 saltStream 将生成一个空字符串。

			// 注意：saltProvider.GenerateStream(nil)
			saltStream := saltProvider.GenerateStream(nil)
			for salt := range saltStream {
				for _, alg := range needSaltAlgos {
					for _, text := range texts {
						jobs <- job{text: text, salt: salt, alg: alg}
					}
				}
			}
		}
	}()

	// Closer
	go func() {
		wg.Wait()
		close(resultsChan)
	}()

	// Collector
	var results []string
	for res := range resultsChan {
		results = append(results, res)
	}

	return results
}
