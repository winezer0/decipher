package cracker

import (
	"decipher/internal/algo"
	"strings"
	"sync"
)

// RunEncrypt 对文本和盐值进行加密，并返回加密结果列表
// 输出格式: Algorithm:hash:salt:plaintext
func (e *Engine) RunEncrypt(textsDicts []string, secretDicts []string, algos []algo.Algorithm) []string {
	// 加载文件到列表
	texts := ParseFilesToStrings(textsDicts, false)
	secrets := ParseFilesToStrings(secretDicts, false)

	// 如果没有盐，就使用空盐罐。
	if len(secrets) == 0 {
		secrets = append(secrets, "") // 哈希字段用作盐值的存储容器
	}

	type job struct {
		text string
		salt string
		alg  algo.Algorithm
	}

	jobs := make(chan job, e.workers)
	resultsChan := make(chan string, e.workers)
	var wg sync.WaitGroup

	// Start workers
	for i := 0; i < e.workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobs {
				token, err := j.alg.Seal(j.text, j.salt)
				if err != nil {
					// 加密失败，跳过此任务
					continue
				}
				// 输出格式：Algorithm:hash:salt:plaintext
				element := []string{j.alg.Name(), token, j.salt, j.text}
				encrypt := strings.Join(element, ConcatSymbol)
				resultsChan <- encrypt
			}
		}()
	}

	// Producer
	go func() {
		for _, alg := range algos {
			for _, text := range texts {
				for _, salt := range secrets {
					jobs <- job{text: text, salt: salt, alg: alg}
				}
			}
		}
		close(jobs)
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
