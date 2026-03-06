package cracker

// SaltProvider 定义 Salt 提供者接口
type SaltProvider interface {
	// Name 返回 Salt 源的名称
	Name() string
	// GenerateStream 返回一个通道，用于流式产生 Salt
	GenerateStream(ctxDone <-chan struct{}) <-chan string
	// Count 返回预估的 Salt 数量（如果无法预估则返回 -1）
	Count() int64
}
