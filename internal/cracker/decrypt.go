package cracker

import (
	"decipher/internal/algo"
	"sync"
	"time"

	"github.com/winezer0/xutils/logging"
)

// RunDecrypt 使用加密/编码算法对密文进行解密
// targets: 待解密的目标列表
// secrets: 密钥列表（可以是字典文件或直接密钥）
// algorithms: 加密算法名称列表
// workers: 并发工作数
func (e *Engine) RunDecrypt(targets []HashSaltTarget, secretDicts []string, decryptAlogs []algo.Algorithm) []CrackerResult {
	workers := e.workers
	var allResults []CrackerResult
	if len(targets) == 0 {
		return allResults
	}

	if len(decryptAlogs) == 0 {
		logging.Warn("No encryption algorithms available for cracking.")
		return allResults
	}

	logging.Infof("Using %d encryption algorithm(s):", len(decryptAlogs))
	for _, a := range decryptAlogs {
		logging.Infof("  - %s", a.Name())
	}

	// 加载密钥源
	secrets := ParseFilesToStrings(secretDicts, true)
	// 如果没有提供密钥，尝试直接解密（对于不需要密钥的编码如 Base64）
	if len(secrets) == 0 {
		secrets = append(secrets, "")
	}

	startTime := time.Now()
	var mu sync.Mutex
	var wg sync.WaitGroup

	// 创建任务通道
	type job struct {
		target HashSaltTarget
		secret string
		alg    algo.Algorithm
	}

	jobs := make(chan job, workers*2)
	resultsChan := make(chan CrackerResult, workers*10)

	// 启动工作协程
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobs {
				// 对于加密算法，调用 Recover 进行解密
				// token: 密文
				// secret: 密钥
				// candidatePlain: 对于解密模式，此参数被忽略
				plaintext, err := j.alg.Recover(j.target.Hash, j.secret, "")
				if err == nil && plaintext != "" {
					result := CrackerResult{
						Hash:      j.target.Hash,
						Algorithm: j.alg.Name(),
						AlgoType:  string(j.alg.GetAlgoType()),
						Plaintext: plaintext,
						Salt:      j.secret,
					}
					resultsChan <- result
				}
			}
		}()
	}

	// 关闭结果通道的协程
	go func() {
		wg.Wait()
		close(resultsChan)
	}()

	// 生产任务
	go func() {
		for _, target := range targets {
			for _, alg := range decryptAlogs {
				for _, secret := range secrets {
					jobs <- job{target: target, secret: secret, alg: alg}
				}
			}
		}
		close(jobs)
	}()

	// 收集结果
	for res := range resultsChan {
		mu.Lock()
		allResults = append(allResults, res)
		mu.Unlock()
		logging.Infof("[+] Decrypt crack success! Hash: %s", res.Hash)
		logging.Infof("    Algorithm: %s", res.Algorithm)
		logging.Infof("    Plaintext: %s", res.Plaintext)
		logging.Infof("    Secret   : %s", res.Salt)
	}

	logging.Infof("Decrypt crack done in %v", time.Since(startTime))
	return allResults
}
