package detector

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os/exec"
	"strings"
	"time"

	"ddos-detector/internal/aggregator"
	"ddos-detector/internal/dashboard"
	"ddos-detector/internal/features"
	"ddos-detector/internal/ml"
	"ddos-detector/internal/runtime"
)

type State string

const (
	StateNormal  State = "NORMAL"
	StateSuspect State = "SUSPECT"
	StateAttack  State = "ATTACK"
)

type Detector struct {
	Model            *ml.LogisticModel
	Params           *runtime.Params
	WebhookURL       string
	EnableMitigation bool
	MitigationScript string

	// Optional in-memory store for the demo dashboard UI.
	Store *dashboard.Store

	state      State
	aboveCount int
	belowCount int
}

func New(model *ml.LogisticModel, params *runtime.Params) *Detector {
	if params == nil {
		params = runtime.NewParams(0.7, 2, 2, 1000)
	}
	return &Detector{
		Model:  model,
		Params: params,
		state:  StateNormal,
	}
}

func (d *Detector) Run(ctx context.Context, in <-chan aggregator.WindowStats) error {
	for {
		select {
		case <-ctx.Done():
			return nil
		case ws := <-in:
			d.processWindow(ws)
		}
	}
}

func (d *Detector) processWindow(ws aggregator.WindowStats) {
	x := features.FeatureVector(ws)

	threshold := d.Params.Threshold()
	confirm := d.Params.ConfirmWindows()
	relax := d.Params.RelaxWindows()

	p := 0.0
	if d.Model != nil {
		// Use the same threshold value as the model's threshold so PredictProba's
		// internal threshold matches what the detector uses for state transitions.
		d.Model.Threshold = threshold
		p = d.Model.PredictProba(x)
	} else {
		p = heuristicScore(ws)
	}

	isAbove := p >= threshold

	if isAbove {
		d.aboveCount++
		d.belowCount = 0
	} else {
		d.belowCount++
		d.aboveCount = 0
	}

	prev := d.state
	switch d.state {
	case StateNormal:
		if isAbove {
			d.state = StateSuspect
		}
	case StateSuspect:
		if isAbove && d.aboveCount >= confirm {
			d.state = StateAttack
		}
		if !isAbove && d.belowCount >= relax {
			d.state = StateNormal
		}
	case StateAttack:
		if !isAbove && d.belowCount >= relax {
			d.state = StateNormal
		}
	}

	// Persist snapshot for dashboard (if enabled).
	if d.Store != nil {
		featuresCopy := make([]float64, len(x))
		copy(featuresCopy, x)

		top := aggregator.TopN(ws.SrcCounts, 5)
		d.Store.Add(dashboard.WindowRecord{
			Ts:          ws.WindowEnd,
			State:       string(d.state),
			Probability: p,
			Threshold:   threshold,
			Metrics: dashboard.WindowMetrics{
				TotalPackets: ws.TotalPackets,
				TotalBytes:   ws.TotalBytes,
				UniqueSrcIPs: ws.UniqueSrcIPs,
				MaxPerSrc:    ws.MaxPerSrc,
				TCPPackets:   ws.TCPPackets,
				UDPPackets:   ws.UDPPackets,
				ICMPPackets:  ws.ICMPPackets,
				TCPSYN:       ws.TCPSYN,
			},
			Features:   featuresCopy,
			TopSources: top,
		})
	}

	// Output
	fmt.Printf("[%s] %s | p=%.3f packets=%d bytes=%d uniqIP=%d maxIP=%d syn=%d tcp=%d udp=%d ent=%.2f\n",
		time.Now().Format(time.RFC3339),
		d.state,
		p,
		ws.TotalPackets, ws.TotalBytes, ws.UniqueSrcIPs, ws.MaxPerSrc,
		ws.TCPSYN, ws.TCPPackets, ws.UDPPackets,
		x[len(x)-1],
	)

	// On transition to ATTACK: alert + mitigation
	if prev != StateAttack && d.state == StateAttack {
		top := aggregator.TopN(ws.SrcCounts, 10)
		d.alert(ws, p, top)
		if d.EnableMitigation && d.MitigationScript != "" {
			_ = d.mitigate(top)
		}
	}
}

func (d *Detector) alert(ws aggregator.WindowStats, p float64, top []string) {
	msg := map[string]any{
		"ts":          ws.WindowEnd.Format(time.RFC3339),
		"state":       d.state,
		"probability": p,
		"metrics": map[string]any{
			"total_packets":  ws.TotalPackets,
			"total_bytes":    ws.TotalBytes,
			"unique_src_ips": ws.UniqueSrcIPs,
			"max_per_src":    ws.MaxPerSrc,
			"tcp_packets":    ws.TCPPackets,
			"udp_packets":    ws.UDPPackets,
			"tcp_syn":        ws.TCPSYN,
		},
		"top_sources": top,
	}

	b, _ := json.MarshalIndent(msg, "", "  ")
	fmt.Println("=== ALERT: Possible DDoS detected ===")
	fmt.Println(string(b))
	fmt.Println("=====================================")

	if d.WebhookURL != "" {
		if err := postJSON(d.WebhookURL, b); err != nil {
			fmt.Println("[detector] webhook error:", err)
		}
	}
}

func postJSON(url string, body []byte) error {
	req, _ := http.NewRequest("POST", url, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	cli := &http.Client{Timeout: 3 * time.Second}
	resp, err := cli.Do(req)
	if err != nil {
		return err
	}
	_ = resp.Body.Close()
	return nil
}

func (d *Detector) mitigate(top []string) error {
	arg := strings.Join(top, ",")
	cmd := exec.Command(d.MitigationScript, arg)
	out, err := cmd.CombinedOutput()
	fmt.Println("Mitigation output:", string(out))
	return err
}

// heuristicScore returns a rough probability estimate without ML model.
func heuristicScore(ws aggregator.WindowStats) float64 {
	score := 0.0
	if ws.TotalPackets > 5000 {
		score += 0.4
	}
	if ws.UniqueSrcIPs > 200 {
		score += 0.3
	}
	if ws.TCPSYN > 1000 {
		score += 0.2
	}
	if ws.MaxPerSrc > 1000 {
		score += 0.1
	}
	if score > 1 {
		score = 1
	}
	return score
}
