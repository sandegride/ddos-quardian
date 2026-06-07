package dashboard

import (
	"sync"
	"time"
)

type WindowMetrics struct {
	TotalPackets int `json:"total_packets"`
	TotalBytes   int `json:"total_bytes"`

	UniqueSrcIPs int `json:"unique_src_ips"`
	MaxPerSrc    int `json:"max_per_src"`

	TCPPackets  int `json:"tcp_packets"`
	UDPPackets  int `json:"udp_packets"`
	ICMPPackets int `json:"icmp_packets"`
	TCPSYN      int `json:"tcp_syn"`

	// Backend health: how the protected service behaved during the window.
	BackendRequests     int     `json:"backend_requests"`
	Backend2xx          int     `json:"backend_2xx"`
	Backend4xx          int     `json:"backend_4xx"`
	Backend5xx          int     `json:"backend_5xx"`
	BackendAvgLatencyMs int     `json:"backend_avg_latency_ms"`
	BackendSuccessRate  float64 `json:"backend_success_rate"`
}

type WindowRecord struct {
	Ts          time.Time     `json:"ts"`
	State       string        `json:"state"`
	Probability float64       `json:"probability"`
	Threshold   float64       `json:"threshold"`
	Metrics     WindowMetrics `json:"metrics"`

	// Optional fields for demos/diagnostics:
	Features   []float64 `json:"features,omitempty"`
	TopSources []string  `json:"top_sources,omitempty"`
}

type Store struct {
	mu      sync.RWMutex
	max     int
	records []WindowRecord
}

func NewStore(max int) *Store {
	if max <= 0 {
		max = 200
	}
	return &Store{
		max:     max,
		records: make([]WindowRecord, 0, max),
	}
}

func (s *Store) Add(r WindowRecord) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.records = append(s.records, r)
	if len(s.records) <= s.max {
		return
	}
	// drop oldest
	cut := len(s.records) - s.max
	tmp := make([]WindowRecord, 0, s.max)
	tmp = append(tmp, s.records[cut:]...)
	s.records = tmp
}

func (s *Store) Latest() (WindowRecord, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if len(s.records) == 0 {
		return WindowRecord{}, false
	}
	return s.records[len(s.records)-1], true
}

func (s *Store) List(limit int) []WindowRecord {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if len(s.records) == 0 {
		return nil
	}
	if limit <= 0 || limit > len(s.records) {
		limit = len(s.records)
	}
	start := len(s.records) - limit
	out := make([]WindowRecord, 0, limit)
	out = append(out, s.records[start:]...)
	return out
}
