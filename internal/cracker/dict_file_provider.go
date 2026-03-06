package cracker

import (
	"bufio"
	"fmt"
	"github.com/winezer0/xutils/logging"
	"os"
	"strings"
)

// FileSaltProvider 基于文件的 Salt 提供者
type FileSaltProvider struct {
	filePath string
}

func NewFileSaltProvider(path string) *FileSaltProvider {
	return &FileSaltProvider{filePath: path}
}

func (p *FileSaltProvider) Name() string {
	return fmt.Sprintf("File:%s", p.filePath)
}

func (p *FileSaltProvider) Count() int64 {
	// 简单的文件行数统计可能比较耗时，这里暂时返回 -1 或尝试快速估算
	// 为避免 IO 瓶颈，暂时返回 -1
	return -1
}

func (p *FileSaltProvider) GenerateStream(ctxDone <-chan struct{}) <-chan string {
	out := make(chan string, 1000)
	go func() {
		defer close(out)
		file, err := os.Open(p.filePath)
		if err != nil {
			logging.Errorf("Failed to open salt file %s: %v", p.filePath, err)
			return
		}
		defer file.Close()

		scanner := bufio.NewScanner(file)
		buf := make([]byte, 0, DefaultScannerBufferSize)
		scanner.Buffer(buf, MaxScannerTokenSize)

		for scanner.Scan() {
			select {
			case <-ctxDone:
				return
			default:
				salt := strings.TrimSpace(scanner.Text())
				if salt != "" {
					out <- salt
				}
			}
		}
		if err := scanner.Err(); err != nil {
			logging.Errorf("Scanner error reading salt file %s: %v", p.filePath, err)
		}
	}()
	return out
}
