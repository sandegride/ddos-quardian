package config

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
)

// Whitelist holds exact IPs and CIDR subnets to exclude from analysis.
// Safe for concurrent reads and replacement.
type Whitelist struct {
	mu      sync.RWMutex
	ips     map[string]struct{}
	nets    []*net.IPNet
	entries []string // original lines (for display in admin UI)
}

// EmptyWhitelist returns an empty Whitelist (no entries).
func EmptyWhitelist() *Whitelist {
	return &Whitelist{ips: make(map[string]struct{})}
}

// Contains returns true if ip matches any exact entry or any CIDR subnet.
func (wl *Whitelist) Contains(ip string) bool {
	wl.mu.RLock()
	defer wl.mu.RUnlock()

	if _, ok := wl.ips[ip]; ok {
		return true
	}
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	for _, n := range wl.nets {
		if n.Contains(parsed) {
			return true
		}
	}
	return false
}

// Entries returns a copy of current whitelist lines (IPs + CIDRs).
func (wl *Whitelist) Entries() []string {
	wl.mu.RLock()
	defer wl.mu.RUnlock()
	out := make([]string, len(wl.entries))
	copy(out, wl.entries)
	return out
}

// ReplaceLines validates and atomically swaps the whitelist contents.
// Comments (#) and blank lines are tolerated.
func (wl *Whitelist) ReplaceLines(lines []string) error {
	ips := make(map[string]struct{})
	var nets []*net.IPNet
	var clean []string

	for i, raw := range lines {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.Contains(line, "/") {
			_, ipNet, err := net.ParseCIDR(line)
			if err != nil {
				return fmt.Errorf("line %d: invalid CIDR %q: %w", i+1, line, err)
			}
			nets = append(nets, ipNet)
			clean = append(clean, line)
			continue
		}
		if net.ParseIP(line) == nil {
			return fmt.Errorf("line %d: invalid IP %q", i+1, line)
		}
		ips[line] = struct{}{}
		clean = append(clean, line)
	}

	wl.mu.Lock()
	wl.ips = ips
	wl.nets = nets
	wl.entries = clean
	wl.mu.Unlock()
	return nil
}

func LoadWhitelist(path string) (*Whitelist, error) {
	wl := EmptyWhitelist()
	if path == "" {
		return wl, nil
	}
	f, err := os.Open(path)
	if err != nil {
		return wl, err
	}
	defer f.Close()

	var lines []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		lines = append(lines, sc.Text())
	}
	if err := sc.Err(); err != nil {
		return wl, err
	}
	if err := wl.ReplaceLines(lines); err != nil {
		return wl, err
	}
	return wl, nil
}
