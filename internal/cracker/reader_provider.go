package cracker

import (
	"decipher/internal/embeds"
	"io"
	"os"

	"github.com/winezer0/xutils/logging"
)

type dictReaderProvider func() (io.ReadSeeker, error)

type dictSource struct {
	Name     string
	Provider dictReaderProvider
}

func InitDictProvider(dicts []string) []dictSource {
	// 将字典转换为合适的类型
	var sources []dictSource
	if len(dicts) > 0 {
		for _, d := range dicts {
			dbPath := d
			sources = append(sources, dictSource{
				Name: dbPath,
				Provider: func() (io.ReadSeeker, error) {
					f, err := os.Open(dbPath)
					if err != nil {
						logging.Errorf("open dict %s occur error:%v", dbPath, err)
						return nil, err
					}
					return f, nil
				},
			})
		}
	} else {
		sources = append(sources, dictSource{
			Name: "Builtin Dict",
			Provider: func() (io.ReadSeeker, error) {
				return embeds.GetBuiltinPlainsDict(), nil
			},
		})
	}
	return sources
}
