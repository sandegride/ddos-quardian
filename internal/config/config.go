package config

import (
	"encoding/json"
	"fmt"
	"os"
)

type Config struct {
	// HTTP proxy mode
	ListenAddr string `json:"listen_addr"`
	BackendURL string `json:"backend_url"`

	// Dashboard UI (web)
	DashboardAddr string `json:"dashboard_addr"`

	// pcap mode (если собирать пакеты)
	Interface string `json:"interface"`
	BPF       string `json:"bpf"`

	WindowMs       int     `json:"window_ms"`
	ModelPath      string  `json:"model_path"`
	Threshold      float64 `json:"threshold"`
	ConfirmWindows int     `json:"confirm_windows"`
	RelaxWindows   int     `json:"relax_windows"`

	WhitelistPath string `json:"whitelist_path"`

	AlertWebhookURL string `json:"alert_webhook_url"`

	EnableMitigation bool   `json:"enable_mitigation"`
	MitigationScript string `json:"mitigation_script"`
}

func Load(path string) (Config, error) {
	var cfg Config
	b, err := os.ReadFile(path)
	if err != nil {
		return cfg, fmt.Errorf("read config: %w", err)
	}
	if err := json.Unmarshal(b, &cfg); err != nil {
		return cfg, fmt.Errorf("parse config json: %w", err)
	}

	if cfg.WindowMs <= 0 {
		cfg.WindowMs = 1000
	}
	if cfg.Threshold <= 0 {
		cfg.Threshold = 0.7
	}
	if cfg.ConfirmWindows <= 0 {
		cfg.ConfirmWindows = 2
	}
	if cfg.RelaxWindows <= 0 {
		cfg.RelaxWindows = 2
	}

	// defaults for demo web dashboard
	if cfg.DashboardAddr == "" {
		cfg.DashboardAddr = ":8090"
	}

	// defaults for HTTP proxy mode
	if cfg.ListenAddr == "" {
		cfg.ListenAddr = ":8080"
	}

	return cfg, nil
}
