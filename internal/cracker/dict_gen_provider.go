package cracker

import (
	"fmt"
	"math"
	"strconv"
	"strings"
)

// GeneratorSaltProvider 自动生成 Salt 的提供者
type GeneratorSaltProvider struct {
	minLen  int
	maxLen  int
	charset string
}

func NewGeneratorSaltProvider(config string) (*GeneratorSaltProvider, error) {
	// config 格式: "gen:minLen:maxLen:charset" 或 "gen:len:charset"
	// 示例: gen:4:6:abcdefg  gen:4:0123456789
	parts := strings.Split(config, ":")
	if len(parts) < 3 {
		return nil, fmt.Errorf("invalid generator config, expected gen:min:max:charset or gen:len:charset")
	}

	var minLen, maxLen int
	var charset string
	var err error

	if len(parts) == 3 {
		// gen:len:charset
		l, err := strconv.Atoi(parts[1])
		if err != nil {
			return nil, fmt.Errorf("invalid length: %v", err)
		}
		minLen = l
		maxLen = l
		charset = parts[2]
	} else {
		// gen:min:max:charset
		minLen, err = strconv.Atoi(parts[1])
		if err != nil {
			return nil, fmt.Errorf("invalid min length: %v", err)
		}
		maxLen, err = strconv.Atoi(parts[2])
		if err != nil {
			return nil, fmt.Errorf("invalid max length: %v", err)
		}
		charset = parts[3]
	}

	if minLen > maxLen {
		minLen, maxLen = maxLen, minLen
	}

	return &GeneratorSaltProvider{
		minLen:  minLen,
		maxLen:  maxLen,
		charset: charset,
	}, nil
}

func (p *GeneratorSaltProvider) Name() string {
	return fmt.Sprintf("Generator(len=%d-%d, charset=%s)", p.minLen, p.maxLen, p.charset)
}

func (p *GeneratorSaltProvider) Count() int64 {
	// 计算组合数
	n := int64(len(p.charset))
	if n == 0 {
		return 0
	}
	var count int64
	for l := p.minLen; l <= p.maxLen; l++ {
		count += int64(math.Pow(float64(n), float64(l)))
	}
	return count
}

func (p *GeneratorSaltProvider) GenerateStream(ctxDone <-chan struct{}) <-chan string {
	out := make(chan string, 1000)
	go func() {
		defer close(out)
		// 使用递归或迭代生成所有组合
		// 为简单起见，这里使用递归
		var generate func(current string)
		generate = func(current string) {
			select {
			case <-ctxDone:
				return
			default:
			}

			if len(current) >= p.minLen {
				out <- current
			}
			if len(current) >= p.maxLen {
				return
			}

			for _, char := range p.charset {
				generate(current + string(char))
			}
		}
		generate("")
	}()
	return out
}

func NormailzeGeneratorRule(ruleString string) (string, bool) {
	if !strings.HasPrefix(ruleString, "gen:") {
		return "", false
	}

	defaultCharset := "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	parts := strings.Split(ruleString, ":")

	switch len(parts) {
	case 2:
		l, err := strconv.Atoi(parts[1])
		if err != nil {
			return "", false
		}
		return "gen:" + strconv.Itoa(l) + ":" + defaultCharset, true
	case 3:
		if maxLen, err := strconv.Atoi(parts[2]); err == nil {
			minLen, err2 := strconv.Atoi(parts[1])
			if err2 != nil {
				return "", false
			}
			return "gen:" + strconv.Itoa(minLen) + ":" + strconv.Itoa(maxLen) + ":" + defaultCharset, true
		}
		if _, err := strconv.Atoi(parts[1]); err != nil {
			return "", false
		}
		if parts[2] == "" {
			return "", false
		}
		return ruleString, true
	case 4:
		if _, err := strconv.Atoi(parts[1]); err != nil {
			return "", false
		}
		if _, err := strconv.Atoi(parts[2]); err != nil {
			return "", false
		}
		if parts[3] == "" {
			return "", false
		}
		return ruleString, true
	default:
		return "", false
	}
}
