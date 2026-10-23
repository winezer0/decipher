package cracker

// MemorySaltProvider 基于内存字符串切片的 Salt 提供者
type MemorySaltProvider struct {
	salts []string
	name  string
}

func NewMemorySaltProvider(salts []string, name string) *MemorySaltProvider {
	return &MemorySaltProvider{salts: salts, name: name}
}

func (p *MemorySaltProvider) Name() string {
	return p.name
}

func (p *MemorySaltProvider) Count() int64 {
	return int64(len(p.salts))
}

func (p *MemorySaltProvider) GenerateStream(ctxDone <-chan struct{}) <-chan string {
	out := make(chan string, min(len(p.salts), saltBufferSize))
	go func() {
		defer close(out)
		for _, s := range p.salts {
			if !sendSalt(ctxDone, out, s) {
				return
			}
		}
	}()
	return out
}
