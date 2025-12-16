package config

import (
	"bufio"
	"os"
	"strings"
)

func LoadWhitelist(path string) (map[string]struct{}, error) {
	wl := make(map[string]struct{})
	if path == "" {
		return wl, nil
	}
	f, err := os.Open(path)
	if err != nil {
		return wl, err
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		wl[line] = struct{}{}
	}
	return wl, sc.Err()
}
