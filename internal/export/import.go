package export

import (
	"bufio"
	"github.com/winezer0/decipher/internal/cracker"
	"encoding/csv"
	"io"
	"os"
	"strings"

	logging "github.com/winezer0/zaplogs"
)

// LoadSuccessCacheMap 逐条读取 CSV，仅保留本次目标；重复哈希取最后一条记录。
// 返回的表只包含已命中项，结果指针均非 nil。
func LoadSuccessCacheMap(cacheFile string, targets []cracker.HashSaltTarget) map[string]*cracker.CrackerResult {
	if len(targets) == 0 {
		return make(map[string]*cracker.CrackerResult)
	}
	f, err := os.Open(cacheFile)
	if err != nil {
		return make(map[string]*cracker.CrackerResult)
	}
	defer f.Close()

	// 目标和结果共用一张表，避免第二张大 map 的查找、扩容和结果结构复制。
	// nil 表示尚未命中；仅在首次命中时分配结果，重复记录就地更新。
	cracked := make(map[string]*cracker.CrackerResult, len(targets))
	for _, target := range targets {
		cracked[strings.ToLower(target.Hash)] = nil
	}
	reader := csv.NewReader(bufio.NewReaderSize(f, 64*1024))
	reader.ReuseRecord = true
	firstRecord := true
	var resultBlock []cracker.CrackerResult
	for {
		record, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			logging.Warnf("Failed to read success cache: %v", err)
			// 与原来的 ReadAll 行为一致：损坏文件中的已读结果也不使用。
			return make(map[string]*cracker.CrackerResult)
		}
		isHeader := firstRecord && len(record) > 0 && strings.EqualFold(record[0], "hash_salt")
		firstRecord = false
		if len(record) == 0 {
			continue
		}
		// Skip header if present
		if isHeader {
			continue
		}

		// CSV Format: hash_salt, clear_text, salt, algo, algo_type
		if len(record) >= 5 {
			// hash_salt
			hash, fallbackSalt, _ := strings.Cut(record[0], cracker.ConcatSymbol)
			hash = strings.TrimSpace(hash)
			key := strings.ToLower(hash)
			result, wanted := cracked[key]
			if !wanted || hash == "" {
				continue
			}

			// plaintext is record[1]
			plaintext := record[1]

			// salt is record[2]
			salt := record[2]
			if salt == "" {
				salt = fallbackSalt
			}

			// algo is record[3]
			algoName := record[3]

			// algo_type is record[4]
			algoType := record[4]

			if result == nil {
				// 按实际命中数分块分配，避免每条结果单独分配；块大小有上限，
				// 不会因目标很多却命中很少而预分配全部结果。
				if len(resultBlock) == 0 {
					resultBlock = make([]cracker.CrackerResult, min(len(targets), 64))
				}
				result = &resultBlock[0]
				resultBlock = resultBlock[1:]
				cracked[key] = result
			}
			*result = cracker.CrackerResult{
				Hash:      hash,
				Salt:      salt,
				Algorithm: algoName,
				AlgoType:  algoType,
				Plaintext: plaintext,
			}
		}
	}
	for hash, result := range cracked {
		if result == nil {
			delete(cracked, hash)
		}
	}
	return cracked
}
