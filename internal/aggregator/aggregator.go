package aggregator

import (
	"context"
	"sort"
	"time"

	"ddos-detector/internal/collector"
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

	// For reporting/top offenders
	SrcCounts map[string]int
}

type Aggregator struct {
	wl map[string]struct{}
}

func New(whitelist map[string]struct{}) *Aggregator {
	if whitelist == nil {
		whitelist = map[string]struct{}{}
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
		// Emit
		out <- ws

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
				if _, ok := a.wl[ev.SrcIP]; ok {
					// ignore whitelisted sources
					continue
				}
				ws.SrcCounts[ev.SrcIP]++
			}
			ws.TotalPackets++
			ws.TotalBytes += ev.Length

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
