package main

import (
	"decipher/internal/cracker"

	"github.com/winezer0/xutils/logging"
)

func main() {
	opts, _ := InitOptionsArgs(1)

	// 解析操作类型
	var modeTypes []cracker.ModeType
	for _, m := range opts.Mode {
		modeTypes = append(modeTypes, cracker.ResolveMode(m))
	}
	logging.Infof("current mode types: %v", modeTypes)

	hasMode := func(target cracker.ModeType) bool {
		for _, m := range modeTypes {
			if m == target {
				return true
			}
		}
		return false
	}

	// 初始化引擎对象 注意 其中也初始化内置字典了
	engine := cracker.NewEngine(opts.Workers, opts.PredbDir, opts.RunCacheDir)

	// 如果是添加模式 (ModeAdd)
	if hasMode(cracker.ModeAdded) {
		// 功能：将用户提供的字典 (-d) 和 盐 (-s) 追加到内置字典文件 (builtin-plain.txt, builtin-salt.txt) 中
		logging.Info("running mode added: appending dictis to builtin files...")
		if err := addedAction(engine, opts); err != nil {
			logging.Errorf("added dicts to embeds dicts error: %s", err)
		} else {
			logging.Info("added dicts to embeds completed.")
		}
	}

	// 识别模式
	if hasMode(cracker.ModeIdent) {
		logging.Info("running mode ident: identify the input string hash algorithm...")
		if err := identAction(engine, opts); err != nil {
			logging.Errorf("ident hashes occur error: %s", err)
		} else {
			logging.Info("ident hashes completed.")
		}
	}

	// 如果是加密模式 调用已选择算法进行加密输出
	if hasMode(cracker.ModeEncrypt) {
		logging.Info("running mode encrypt: encrypt the input string to hash...")
		if err := encryptAction(engine, opts); err != nil {
			logging.Errorf("encrypt string to hashes occur error: %s", err)
		} else {
			logging.Info("encrypt string to hashes completed.")
		}
	}

	// 如果是解密模式 调用已选择算法进行密文解密
	if hasMode(cracker.ModeDecrypt) {
		logging.Info("running mode decrypt: decrypt the hashes to plain...")
		if err := decryptAction(engine, opts); err != nil {
			logging.Errorf("decrypt hashes occur error: %s", err)
		} else {
			logging.Info("decrypt hashes to plain completed.")
		}
	}
}
