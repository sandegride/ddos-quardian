// Package runtime keeps hot-reloadable detector parameters guarded by an RWMutex.
// The detector reads them on every window; admin handlers update them at any time.
package runtime

import (
	"fmt"
	"sync"
)

type Snapshot struct {
	Threshold      float64 `json:"threshold"`
	ConfirmWindows int     `json:"confirm_windows"`
	RelaxWindows   int     `json:"relax_windows"`
	WindowMs       int     `json:"window_ms"`
}

type Params struct {
	mu             sync.RWMutex
	threshold      float64
	confirmWindows int
	relaxWindows   int
	windowMs       int
}

func NewParams(threshold float64, confirm, relax, windowMs int) *Params {
	if threshold <= 0 {
		threshold = 0.7
	}
	if confirm <= 0 {
		confirm = 2
	}
	if relax <= 0 {
		relax = 2
	}
	if windowMs <= 0 {
		windowMs = 1000
	}
	return &Params{
		threshold:      threshold,
		confirmWindows: confirm,
		relaxWindows:   relax,
		windowMs:       windowMs,
	}
}

func (p *Params) Snapshot() Snapshot {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return Snapshot{
		Threshold:      p.threshold,
		ConfirmWindows: p.confirmWindows,
		RelaxWindows:   p.relaxWindows,
		WindowMs:       p.windowMs,
	}
}

func (p *Params) Threshold() float64 {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.threshold
}

func (p *Params) ConfirmWindows() int {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.confirmWindows
}

func (p *Params) RelaxWindows() int {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.relaxWindows
}

// Update applies new values. window_ms is read-only at runtime (changing it
// would require restarting the aggregator goroutine); it is ignored here.
func (p *Params) Update(s Snapshot) error {
	if s.Threshold <= 0 || s.Threshold > 1 {
		return fmt.Errorf("threshold must be in (0, 1], got %v", s.Threshold)
	}
	if s.ConfirmWindows < 1 || s.ConfirmWindows > 100 {
		return fmt.Errorf("confirm_windows must be in [1, 100], got %d", s.ConfirmWindows)
	}
	if s.RelaxWindows < 1 || s.RelaxWindows > 100 {
		return fmt.Errorf("relax_windows must be in [1, 100], got %d", s.RelaxWindows)
	}
	p.mu.Lock()
	p.threshold = s.Threshold
	p.confirmWindows = s.ConfirmWindows
	p.relaxWindows = s.RelaxWindows
	p.mu.Unlock()
	return nil
}
