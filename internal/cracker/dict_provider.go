package cracker

const saltBufferSize = 1000

// 缓冲可写时避免完整的多路 select；只有发送会阻塞时才等待发送或取消。
func sendSalt(done <-chan struct{}, out chan<- string, salt string) bool {
	select {
	case <-done:
		return false
	default:
	}
	return sendSaltAfterCheck(done, out, salt)
}

// 调用方刚检查过取消信号，避免在每个值上重复轮询。
func sendSaltAfterCheck(done <-chan struct{}, out chan<- string, salt string) bool {
	select {
	case out <- salt:
		return true
	default:
	}
	select {
	case <-done:
		return false
	case out <- salt:
		return true
	}
}

// 只读取内置内存来源的已知长度；未知来源保持原上限，不调用可能昂贵或有副作用的 Count。
// 提示只用于预留容量，不能据此跳过来源或限制输出数量。
func saltBufferCapacity(providers []SaltProvider) int {
	total := 0
	for _, provider := range providers {
		switch p := provider.(type) {
		case *MemorySaltProvider:
			total += min(len(p.salts), saltBufferSize-total)
		case *MultiSaltProvider:
			total += min(saltBufferCapacity(p.providers), saltBufferSize-total)
		default:
			return saltBufferSize
		}
		if total == saltBufferSize {
			return total
		}
	}
	return total
}

// SaltProvider 定义 Salt 提供者接口
type SaltProvider interface {
	// Name 返回 Salt 源的名称
	Name() string
	// GenerateStream 返回一个通道，用于流式产生 Salt
	GenerateStream(ctxDone <-chan struct{}) <-chan string
	// Count 返回预估的 Salt 数量（如果无法预估则返回 -1）
	Count() int64
}
