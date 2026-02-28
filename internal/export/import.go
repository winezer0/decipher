package export

import (
	"decipher/internal/cracker"
	"encoding/csv"
	"os"
	"strings"

	"github.com/winezer0/xutils/logging"
)

// LoadSuccessCacheMap 从 CSV 文件加载已解密的缓存结果
func LoadSuccessCacheMap(cacheFile string) map[string]cracker.CrackerResult {
	cracked := make(map[string]cracker.CrackerResult)
	f, err := os.Open(cacheFile)
	if err != nil {
		return cracked
	}
	defer f.Close()

	reader := csv.NewReader(f)
	records, err := reader.ReadAll()
	if err != nil {
		logging.Warnf("Failed to read success cache: %v", err)
		return cracked
	}

	for i, record := range records {
		if len(record) == 0 {
			continue
		}
		// Skip header if present
		if i == 0 && strings.EqualFold(record[0], "hash_salt") {
			continue
		}

		// CSV Format: hash_salt, clear_text, salt, algo, algo_type
		if len(record) >= 5 {
			// hash_salt
			parts := strings.SplitN(record[0], ":", 2)
			hash := strings.TrimSpace(parts[0])

			// plaintext is record[1]
			plaintext := record[1]

			// salt is record[2]
			salt := record[2]
			if salt == "" && len(parts) > 1 {
				salt = parts[1]
			}

			// algo is record[3]
			algoName := record[3]

			// algo_type is record[4]
			algoType := record[4]

			if hash != "" {
				cracked[strings.ToLower(hash)] = cracker.CrackerResult{
					Hash:      hash,
					Salt:      salt,
					Algorithm: algoName,
					AlgoType:  algoType,
					Plaintext: plaintext,
				}
			}
		}
	}
	return cracked
}
