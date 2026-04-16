package config

import (
	"bufio"
	"net"
	"os"
	"strings"
)

// Whitelist holds exact IPs and CIDR subnets to exclude from analysis.
type Whitelist struct {
	ips  map[string]struct{}
	nets []*net.IPNet
}

// EmptyWhitelist returns an empty Whitelist (no entries).
func EmptyWhitelist() *Whitelist {
	return &Whitelist{ips: make(map[string]struct{})}
}

// Contains returns true if ip matches any exact entry or any CIDR subnet.
func (wl *Whitelist) Contains(ip string) bool {
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

func LoadWhitelist(path string) (*Whitelist, error) {
	wl := &Whitelist{ips: make(map[string]struct{})}
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
		if strings.Contains(line, "/") {
			_, ipNet, err := net.ParseCIDR(line)
			if err == nil {
				wl.nets = append(wl.nets, ipNet)
				continue
			}
		}
		wl.ips[line] = struct{}{}
	}
	return wl, sc.Err()
}
