package cracker

import "context"

// crackWorker 的策略和盐批次均只读；任务局部前后缀缓冲仅属于当前 Worker。
func (e *Engine) crackWorker(ctx context.Context, taskChan <-chan crackTask, resultChan chan<- CrackerResult, strategies crackStrategies) {
	var affixedSalts []string
	done := ctx.Done()
	for {
		var task crackTask
		select {
		case <-done:
			return
		case next, ok := <-taskChan:
			if !ok {
				return
			}
			task = next
		}
		if task.plainLine == "" {
			continue
		}
		fixedPass := len(task.salts) == 0
		selected := strategies.dynamic
		if fixedPass {
			selected = strategies.fixed
		}
		if len(selected) == 0 {
			continue
		}
		plain := e.AffixPasswd(task.plainLine)
		if fixedPass && strategies.fixedPlainDigest != nil {
			candidate := strategies.fixedPlainDigest(plain)
			for _, strategy := range selected {
				select {
				case <-done:
					return
				default:
				}
				if *strategy.prepared != candidate {
					continue
				}
				alg := strategy.validAlgos[0]
				result := CrackerResult{Hash: strategy.target.Hash, Salt: strategy.target.Salt, Plaintext: plain, Algorithm: alg.Name(), AlgoType: string(alg.GetAlgoType())}
				select {
				case <-done:
					return
				case resultChan <- result:
				}
			}
			continue
		}
		secrets := task.salts
		if !fixedPass && task.affixedSalts != nil {
			secrets = task.affixedSalts.values
		} else if !fixedPass && (e.SaltPrefix != "" || e.SaltSuffix != "") {
			// 仅复用当前任务的盐字符串切片，不缓存候选计算结果或跨任务盐内容。
			if cap(affixedSalts) < len(task.salts) {
				affixedSalts = make([]string, len(task.salts))
			} else {
				affixedSalts = affixedSalts[:len(task.salts)]
			}
			for i, salt := range task.salts {
				affixedSalts[i] = e.AffixSalt(salt)
			}
			secrets = affixedSalts
		}
		for _, strategy := range selected {
			target := strategy.target
			salts := task.salts
			if fixedPass {
				salts = []string{target.Salt}
			}
			for i, salt := range salts {
				secret := strategy.secret
				if !fixedPass {
					secret = secrets[i]
				}
				for _, alg := range strategy.validAlgos {
					select {
					case <-done:
						return
					default:
					}
					var recovered string
					var err error
					if alg.recoverPrepared != nil {
						recovered, err = alg.recoverPrepared(strategy.prepared, secret, plain)
					} else {
						recovered, err = alg.Recover(target.Hash, secret, plain)
					}
					if err != nil {
						continue
					}
					result := CrackerResult{Hash: target.Hash, AlgoType: string(alg.GetAlgoType()), Algorithm: alg.Name(), Plaintext: recovered, Salt: salt}
					select {
					case <-done:
						return
					case resultChan <- result:
					}
					goto NextTarget
				}
			}
		NextTarget:
		}
		clear(affixedSalts)
	}
}
