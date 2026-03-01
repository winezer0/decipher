package cracker

import (
	"decipher/internal/algo"
	"fmt"
	"sync"
)

// RunEncrypt 对文本和盐值进行加密，并返回加密结果列表
// 输出格式: Algorithm:hash:salt:plaintext
func (e *Engine) RunEncrypt(texts []Target, salts []Target, algos []algo.Algorithm) []string {
	workers := e.workers

	// If no salts, use empty salt
	if len(salts) == 0 {
		salts = append(salts, Target{Hash: ""}) // Hash field used as content holder for salt
	}

	type job struct {
		text string
		salt string
		alg  algo.Algorithm
	}

	jobs := make(chan job, workers)
	resultsChan := make(chan string, workers)
	var wg sync.WaitGroup

	// Start workers
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobs {
				token, err := j.alg.Seal(j.text, j.salt)
				if err != nil {
					// 加密失败，跳过此任务
					continue
				}
				// Output format: Algorithm:hash:salt:plaintext
				resultsChan <- fmt.Sprintf("%s:%s:%s:%s", j.alg.Name(), token, j.salt, j.text)
			}
		}()
	}

	// Producer
	go func() {
		for _, alg := range algos {
			for _, textTarget := range texts {
				text := textTarget.Hash // ParseStringsToTargets puts content in Hash field

				// Cartesian product of texts and salts
				for _, saltTarget := range salts {
					salt := saltTarget.Hash // ParseStringsToTargets puts content in Hash field
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
