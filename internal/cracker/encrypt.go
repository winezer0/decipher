package cracker

import (
	"context"
	"strings"
	"sync"

	"github.com/winezer0/decipher/internal/algo"
	logging "github.com/winezer0/zaplogs"
)

type EncryptResult struct {
	Algorithm string `json:"algorithm"`
	Hash      string `json:"hash"`
	Salt      string `json:"salt"`
	Plaintext string `json:"plaintext"`
}

func (r EncryptResult) String() string {
	return strings.Join([]string{r.Algorithm, r.Hash, r.Salt, r.Plaintext}, ConcatSymbol)
}

// RunEncrypt 保留原有文本结果接口，供控制台及现有调用方使用。
func (e *Engine) RunEncrypt(plainDicts []string, secretDicts []string, algos []algo.Algorithm) []string {
	results := e.RunEncryptResults(plainDicts, secretDicts, algos)
	lines := make([]string, 0, len(results))
	for _, result := range results {
		lines = append(lines, result.String())
	}
	return lines
}

// RunEncryptResults 保留各字段的原始边界，供 CSV/JSON 序列化使用。
func (e *Engine) RunEncryptResults(plainDicts []string, secretDicts []string, algos []algo.Algorithm) []EncryptResult {
	results := make([]EncryptResult, 0)
	_ = e.RunEncryptStream(plainDicts, secretDicts, algos, func(result EncryptResult) error {
		results = append(results, result)
		return nil
	})
	return results
}

// RunEncryptStream 串行交付并发计算的结果；消费失败后取消任务并等待生产者和计算协程退出。
// 结果顺序与原收集接口一致，取决于并发任务的完成顺序。算法计算失败仍跳过该任务。
func (e *Engine) RunEncryptStream(plainDicts []string, secretDicts []string, algos []algo.Algorithm, emit func(EncryptResult) error) error {
	texts := ReadFilesToStrings(plainDicts, false)
	providers := InitSaltProviders(secretDicts)
	if len(providers) == 0 {
		logging.Warnf("InitSaltProviders returned empty list, using empty salt")
		providers = InitValueSaltProviders(nil)
	}
	return e.runEncryptStream(texts, NewMultiSaltProvider(providers), algos, emit)
}

// RunEncryptValuesStream encrypts in-memory plaintexts and secrets and emits structured results.
func (e *Engine) RunEncryptValuesStream(plaintexts, secrets []string, algos []algo.Algorithm, emit func(EncryptResult) error) error {
	texts := append([]string(nil), plaintexts...)
	return e.runEncryptStream(texts, NewMultiSaltProvider(InitValueSaltProviders(secrets)), algos, emit)
}

// runEncryptStream runs the shared worker pipeline for an in-memory plaintext list and salt provider.
func (e *Engine) runEncryptStream(texts []string, saltProvider SaltProvider, algos []algo.Algorithm, emit func(EncryptResult) error) error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	logging.Infof("Loaded %d text(s) to encrypt", len(texts))
	hasPassAffixes := e.PassPrefix != "" || e.PassSuffix != ""
	var preparedText []bool
	if hasPassAffixes {
		preparedText = make([]bool, len(texts))
	}
	// logging.Infof("Loaded %d salt(s) to use", len(secrets)) // 无法预知总数

	type job struct {
		text        string
		plaintext   string
		salt        string
		affixedSalt string
		algorithm   algo.Algorithm
	}

	jobs := make(chan job, e.workers*2)
	resultsChan := make(chan EncryptResult, e.workers*10)
	var wg sync.WaitGroup

	// Start workers
	for i := 0; i < e.workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobs {
				if ctx.Err() != nil {
					return
				}
				hash, err := j.algorithm.Seal(j.plaintext, j.affixedSalt)
				if err != nil {
					// 加密失败，跳过此任务
					continue
				}
				select {
				case resultsChan <- EncryptResult{Algorithm: j.algorithm.Name(), Hash: hash, Salt: j.salt, Plaintext: j.text}:
				case <-ctx.Done():
					return
				}
			}
		}()
	}

	// Producer
	producerDone := make(chan struct{})
	go func() {
		defer close(producerDone)
		defer close(jobs)
		send := func(j job) bool {
			select {
			case jobs <- j:
				return true
			case <-ctx.Done():
				return false
			}
		}

		// 明文加载一次；无盐算法运行一次，有盐算法复用同一条盐流。
		var needSaltAlgos []algo.Algorithm
		var noSaltAlgos []algo.Algorithm
		for _, a := range algos {
			if a.NeedSalt() {
				needSaltAlgos = append(needSaltAlgos, a)
			} else {
				noSaltAlgos = append(noSaltAlgos, a)
			}
		}
		prepareText := func(index int) (string, string) {
			if !hasPassAffixes {
				return texts[index], texts[index]
			}
			if !preparedText[index] {
				texts[index] = e.AffixPasswd(texts[index])
				preparedText[index] = true
			}
			plaintext := texts[index]
			text := plaintext[len(e.PassPrefix) : len(plaintext)-len(e.PassSuffix)]
			return text, plaintext
		}

		// 1. 处理不需要 Salt 的算法
		for _, alg := range noSaltAlgos {
			for i := range texts {
				text, plaintext := prepareText(i)
				if !send(job{text: text, plaintext: plaintext, algorithm: alg}) {
					return
				}
			}
		}

		// 2. 处理需要 Salt 的算法
		if len(needSaltAlgos) > 0 {
			saltStream := saltProvider.GenerateStream(ctx.Done())
			// 部分提供者在发送前检查取消信号；排空通道以释放已阻塞的发送。
			defer func() {
				for range saltStream {
				}
			}()
			for salt := range saltStream {
				affixedSalt := e.AffixSalt(salt)
				for _, alg := range needSaltAlgos {
					for i := range texts {
						text, plaintext := prepareText(i)
						if !send(job{text: text, plaintext: plaintext, salt: salt, affixedSalt: affixedSalt, algorithm: alg}) {
							return
						}
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
	var emitErr error
	for res := range resultsChan {
		if emitErr == nil {
			emitErr = emit(res)
			if emitErr != nil {
				cancel()
			}
		}
	}
	<-producerDone
	return emitErr
}
