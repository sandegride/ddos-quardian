package features

import (
	"math"

	"ddos-detector/internal/aggregator"
)

// FeatureVector builds a fixed-order vector of numeric features for ML.
// Order must be consistent between training and inference.
func FeatureVector(ws aggregator.WindowStats) []float64 {
	total := float64(ws.TotalPackets)
	if total <= 0 {
		total = 1
	}

	tcpRatio := float64(ws.TCPPackets) / total
	udpRatio := float64(ws.UDPPackets) / total
	icmpRatio := float64(ws.ICMPPackets) / total
	synRatio := 0.0
	if ws.TCPPackets > 0 {
		synRatio = float64(ws.TCPSYN) / float64(ws.TCPPackets)
	}

	// Entropy of src distribution (normalized by log2(k))
	ent := SrcEntropy(ws.SrcCounts)

	avgPktSize := float64(ws.TotalBytes) / total

	// Basic features
	return []float64{
		float64(ws.TotalPackets),
		float64(ws.TotalBytes),
		float64(ws.UniqueSrcIPs),
		float64(ws.MaxPerSrc),
		avgPktSize,
		tcpRatio,
		udpRatio,
		icmpRatio,
		synRatio,
		ent,
	}
}

// SrcEntropy computes normalized entropy in [0..1] for the source distribution.
func SrcEntropy(src map[string]int) float64 {
	n := 0
	for _, c := range src {
		n += c
	}
	if n <= 0 {
		return 0
	}
	k := len(src)
	if k <= 1 {
		return 0
	}
	// H = - sum p_i log2 p_i ; normalize by log2(k)
	H := 0.0
	for _, c := range src {
		p := float64(c) / float64(n)
		if p > 0 {
			H -= p * (math.Log(p) / math.Log(2))
		}
	}
	Hmax := math.Log(float64(k)) / math.Log(2)
	if Hmax <= 0 {
		return 0
	}
	return H / Hmax
}

func FeatureNames() []string {
	return []string{
		"total_packets",
		"total_bytes",
		"unique_src_ips",
		"max_per_src",
		"avg_pkt_size",
		"tcp_ratio",
		"udp_ratio",
		"icmp_ratio",
		"syn_ratio",
		"src_entropy",
	}
}
