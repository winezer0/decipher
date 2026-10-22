package main

import (
	"errors"
	"fmt"
	"os"
)

// tempFiles tracks only files created by the current action, including partial results.
type tempFiles struct {
	remove bool
	paths  []string
}

func (t *tempFiles) resolve(inputs []string, dir, kind string) ([]string, []string, error) {
	paths, temps, err := resolveDictsPrefix(inputs, dir, kind)
	t.paths = append(t.paths, temps...)
	return paths, temps, err
}

func (t *tempFiles) cleanup(result *error) {
	if !t.remove {
		return
	}
	for _, path := range t.paths {
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			*result = errors.Join(*result, fmt.Errorf("remove temporary file %q: %w", path, err))
		}
	}
}
