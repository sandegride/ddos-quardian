// Package loadgen runs a phased HTTP load scenario against the local proxy.
// It is intentionally limited to 127.0.0.1 so the demo cannot be turned into
// a real DoS tool.
package loadgen

import (
	"context"
	"fmt"
	"math/rand"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Phase is one segment of a scenario.
type Phase struct {
	Name         string  `json:"name"` // "normal" | "attack" | "recovery" | any label
	DurationSec  int     `json:"duration_sec"`
	Workers      int     `json:"workers"`        // concurrent goroutines
	RPSPerWorker float64 `json:"rps_per_worker"` // 0 = max speed (no sleep)
	SpoofIPs     bool    `json:"spoof_ips"`      // true = random X-Forwarded-For, false = pool of 20 legit IPs
}

type Scenario struct {
	Phases []Phase `json:"phases"`
}

// DefaultDemoScenario mirrors the k6 loadtest.js stages.
func DefaultDemoScenario() Scenario {
	return Scenario{Phases: []Phase{
		{Name: "normal", DurationSec: 30, Workers: 50, RPSPerWorker: 1.0, SpoofIPs: false},
		{Name: "attack", DurationSec: 60, Workers: 1500, RPSPerWorker: 0, SpoofIPs: true},
		{Name: "recovery", DurationSec: 30, Workers: 30, RPSPerWorker: 1.0, SpoofIPs: false},
	}}
}

type Status struct {
	Running     bool   `json:"running"`
	Phase       string `json:"phase"`
	PhaseIndex  int    `json:"phase_index"`
	PhasesTotal int    `json:"phases_total"`
	ElapsedSec  int    `json:"elapsed_sec"`
	TotalSec    int    `json:"total_sec"`
	Sent        int64  `json:"sent"`
	Errors      int64  `json:"errors"`
	RPS         int    `json:"rps"` // sent/elapsed (average over current phase)
	StartedAt   string `json:"started_at,omitempty"`
}

type Runner struct {
	target string // e.g. "http://127.0.0.1:8080"
	client *http.Client

	mu      sync.Mutex
	cancel  context.CancelFunc
	running bool
	started time.Time
	status  atomicStatus
}

type atomicStatus struct {
	mu sync.RWMutex
	s  Status
}

func (a *atomicStatus) load() Status {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.s
}

func (a *atomicStatus) store(s Status) {
	a.mu.Lock()
	a.s = s
	a.mu.Unlock()
}

func New(listenAddr string) *Runner {
	host := listenAddr
	if strings.HasPrefix(host, ":") {
		host = "127.0.0.1" + host
	}
	tr := &http.Transport{
		MaxIdleConns:        2048,
		MaxIdleConnsPerHost: 2048,
		IdleConnTimeout:     30 * time.Second,
		DisableCompression:  true,
	}
	return &Runner{
		target: "http://" + host,
		client: &http.Client{Transport: tr, Timeout: 5 * time.Second},
	}
}

func (r *Runner) Target() string { return r.target }

func (r *Runner) Status() Status {
	return r.status.load()
}

// Start launches the scenario. Returns error if a scenario is already running
// or the scenario is invalid.
func (r *Runner) Start(scn Scenario) error {
	r.mu.Lock()
	if r.running {
		r.mu.Unlock()
		return fmt.Errorf("loadtest already running")
	}
	if len(scn.Phases) == 0 {
		r.mu.Unlock()
		return fmt.Errorf("scenario has no phases")
	}
	total := 0
	for i, p := range scn.Phases {
		if p.DurationSec <= 0 {
			r.mu.Unlock()
			return fmt.Errorf("phase %d (%s): duration_sec must be > 0", i, p.Name)
		}
		if p.Workers <= 0 || p.Workers > 5000 {
			r.mu.Unlock()
			return fmt.Errorf("phase %d (%s): workers must be in [1, 5000]", i, p.Name)
		}
		total += p.DurationSec
	}

	ctx, cancel := context.WithCancel(context.Background())
	r.cancel = cancel
	r.running = true
	r.started = time.Now()
	r.mu.Unlock()

	r.status.store(Status{
		Running:     true,
		PhasesTotal: len(scn.Phases),
		TotalSec:    total,
		StartedAt:   r.started.Format(time.RFC3339),
	})

	go r.run(ctx, scn, total)
	return nil
}

func (r *Runner) Stop() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.cancel != nil {
		r.cancel()
	}
}

func (r *Runner) run(ctx context.Context, scn Scenario, total int) {
	var sent, errs int64
	phaseStart := time.Now()
	runStart := time.Now()

	statusTick := time.NewTicker(500 * time.Millisecond)
	defer statusTick.Stop()

	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-statusTick.C:
				cur := r.status.load()
				elapsed := int(time.Since(runStart).Seconds())
				phaseElapsed := time.Since(phaseStart).Seconds()
				rps := 0
				if phaseElapsed > 0.1 {
					rps = int(float64(atomic.LoadInt64(&sent)-cur.Sent) / phaseElapsed)
					_ = rps // we compute fresh below
				}
				cur.ElapsedSec = elapsed
				cur.Sent = atomic.LoadInt64(&sent)
				cur.Errors = atomic.LoadInt64(&errs)
				if elapsed > 0 {
					cur.RPS = int(cur.Sent / int64(elapsed))
				}
				r.status.store(cur)
			}
		}
	}()

	for i, p := range scn.Phases {
		select {
		case <-ctx.Done():
			r.finish()
			return
		default:
		}

		cur := r.status.load()
		cur.Phase = p.Name
		cur.PhaseIndex = i
		r.status.store(cur)
		phaseStart = time.Now()

		r.runPhase(ctx, p, &sent, &errs)
	}

	r.finish()
}

func (r *Runner) finish() {
	r.mu.Lock()
	r.running = false
	r.cancel = nil
	r.mu.Unlock()

	cur := r.status.load()
	cur.Running = false
	cur.Phase = "done"
	r.status.store(cur)
}

func (r *Runner) runPhase(ctx context.Context, p Phase, sent, errs *int64) {
	phaseCtx, cancel := context.WithTimeout(ctx, time.Duration(p.DurationSec)*time.Second)
	defer cancel()

	var wg sync.WaitGroup
	wg.Add(p.Workers)
	for w := 0; w < p.Workers; w++ {
		go func(id int) {
			defer wg.Done()
			r.worker(phaseCtx, p, id, sent, errs)
		}(w)
	}
	wg.Wait()
}

var legitIPs = func() []string {
	ips := make([]string, 20)
	for i := 0; i < 20; i++ {
		ips[i] = fmt.Sprintf("10.0.0.%d", i+1)
	}
	return ips
}()

var paths = []string{"/", "/index.html", "/api/health", "/style.css"}

func (r *Runner) worker(ctx context.Context, p Phase, id int, sent, errs *int64) {
	rng := rand.New(rand.NewSource(time.Now().UnixNano() + int64(id)))

	var interval time.Duration
	if p.RPSPerWorker > 0 {
		interval = time.Duration(float64(time.Second) / p.RPSPerWorker)
	}

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		ip := legitIPs[rng.Intn(len(legitIPs))]
		if p.SpoofIPs {
			ip = fmt.Sprintf("%d.%d.%d.%d",
				rng.Intn(223)+1, rng.Intn(256), rng.Intn(256), rng.Intn(254)+1)
		}
		path := paths[rng.Intn(len(paths))]

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, r.target+path, nil)
		if err != nil {
			atomic.AddInt64(errs, 1)
			return
		}
		req.Header.Set("X-Forwarded-For", ip)

		resp, err := r.client.Do(req)
		atomic.AddInt64(sent, 1)
		if err != nil {
			atomic.AddInt64(errs, 1)
		} else {
			if resp.StatusCode >= 400 {
				atomic.AddInt64(errs, 1)
			}
			_ = resp.Body.Close()
		}

		if interval > 0 {
			// jitter ±20% so workers don't sync
			j := time.Duration(rng.Int63n(int64(interval / 5)))
			select {
			case <-ctx.Done():
				return
			case <-time.After(interval + j - interval/10):
			}
		}
	}
}
