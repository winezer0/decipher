package cracker

import (
	"fmt"
)

// MultiSaltProvider 组合多个 SaltProvider
type MultiSaltProvider struct {
	providers []SaltProvider
}

func NewMultiSaltProvider(providers []SaltProvider) *MultiSaltProvider {
	return &MultiSaltProvider{providers: providers}
}

func (p *MultiSaltProvider) Name() string {
	return fmt.Sprintf("MultiSaltProvider(%d providers)", len(p.providers))
}

func (p *MultiSaltProvider) Count() int64 {
	var total int64
	for _, provider := range p.providers {
		c := provider.Count()
		if c == -1 {
			return -1
		}
		total += c
	}
	return total
}

func (p *MultiSaltProvider) GenerateStream(ctxDone <-chan struct{}) <-chan string {
	out := make(chan string, 1000)
	go func() {
		defer close(out)
		// seen := make(map[string]struct{}) // 移除全局去重以防止 OOM

		for _, provider := range p.providers {
			ch := provider.GenerateStream(ctxDone)
			for salt := range ch {
				// if _, exists := seen[salt]; !exists {
				// 	seen[salt] = struct{}{}
				// 	out <- salt
				// }
				// 直接输出，允许重复以换取内存安全
				select {
				case <-ctxDone:
					return
				case out <- salt:
				}
			}
		}
	}()
	return out
}
