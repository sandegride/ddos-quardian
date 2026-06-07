package aggregator

import (
	"context"
	"fmt"
	"sort"
	"time"

	"ddos-detector/internal/collector"
	"ddos-detector/internal/config"
)

type WindowStats struct {
	WindowStart time.Time
	WindowEnd   time.Time

	TotalPackets int
	TotalBytes   int

	UniqueSrcIPs int
	MaxPerSrc    int

	TCPPackets   int
	UDPPackets   int
	ICMPPackets  int
	OtherPackets int

	TCPSYN int
	TCPACK int

	// Backend health metrics (HTTP mode). Filled from collector PacketEvents.
	BackendRequests     int // total requests where the proxy attempted the backend
	Backend2xx          int
	Backend4xx          int
	Backend5xx          int
	BackendLatencySumMs int

	// For reporting/top offenders
	SrcCounts map[string]int
}

// BackendAvgLatencyMs returns the mean backend latency in milliseconds, or 0
// if no backend requests were recorded in the window.
func (w WindowStats) BackendAvgLatencyMs() int {
	if w.BackendRequests == 0 {
		return 0
	}
	return w.BackendLatencySumMs / w.BackendRequests
}

// BackendSuccessRate returns the share of 2xx responses in (0..1], or 0 when
// there were no backend requests.
func (w WindowStats) BackendSuccessRate() float64 {
	if w.BackendRequests == 0 {
		return 0
	}
	return float64(w.Backend2xx) / float64(w.BackendRequests)
}

type Aggregator struct {
	wl *config.Whitelist
}

func New(whitelist *config.Whitelist) *Aggregator {
	if whitelist == nil {
		whitelist = config.EmptyWhitelist()
	}
	return &Aggregator{wl: whitelist}
}

// Run aggregates PacketEvent into windows and emits WindowStats every windowDur.
func (a *Aggregator) Run(ctx context.Context, in <-chan collector.PacketEvent, windowDur time.Duration, out chan<- WindowStats) error {
	ticker := time.NewTicker(windowDur)
	defer ticker.Stop()

	var ws WindowStats
	ws.SrcCounts = make(map[string]int)
	ws.WindowStart = time.Now()

	flush := func(end time.Time) {
		ws.WindowEnd = end
		ws.UniqueSrcIPs = len(ws.SrcCounts)
		for _, v := range ws.SrcCounts {
			if v > ws.MaxPerSrc {
				ws.MaxPerSrc = v
			}
		}
		// Non-blocking emit: drop window if detector is slow and log warning.
		select {
		case out <- ws:
		default:
			fmt.Println("[aggregator] warning: window channel full, dropping window")
		}

		// Reset
		ws = WindowStats{
			WindowStart: end,
			SrcCounts:   make(map[string]int),
		}
	}

	for {
		select {
		case <-ctx.Done():
			return nil
		case ev := <-in:
			if ev.SrcIP != "" {
				if a.wl.Contains(ev.SrcIP) {
					// ignore whitelisted sources
					continue
				}
				ws.SrcCounts[ev.SrcIP]++
			}
			ws.TotalPackets++
			ws.TotalBytes += ev.Length

			if ev.BackendStatus != 0 {
				ws.BackendRequests++
				ws.BackendLatencySumMs += ev.BackendLatencyMs
				switch {
				case ev.BackendStatus >= 200 && ev.BackendStatus < 300:
					ws.Backend2xx++
				case ev.BackendStatus >= 400 && ev.BackendStatus < 500:
					ws.Backend4xx++
				case ev.BackendStatus >= 500:
					ws.Backend5xx++
				}
			}

			switch ev.Proto {
			case "TCP":
				ws.TCPPackets++
				if ev.TCPSYN {
					ws.TCPSYN++
				}
				if ev.TCPACK {
					ws.TCPACK++
				}
			case "UDP":
				ws.UDPPackets++
			case "ICMP":
				ws.ICMPPackets++
			default:
				ws.OtherPackets++
			}
		case t := <-ticker.C:
			flush(t)
		}
	}
}

// TopN returns top N sources by packet count.
func TopN(m map[string]int, n int) []string {
	type kv struct {
		k string
		v int
	}
	arr := make([]kv, 0, len(m))
	for k, v := range m {
		arr = append(arr, kv{k: k, v: v})
	}
	sort.Slice(arr, func(i, j int) bool { return arr[i].v > arr[j].v })
	if n > len(arr) {
		n = len(arr)
	}
	res := make([]string, 0, n)
	for i := 0; i < n; i++ {
		res = append(res, arr[i].k)
	}
	return res
}
