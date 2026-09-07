package patrol

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"
)

type RunnerConfig struct {
	Interval  time.Duration
	Timeout   time.Duration
	Journal   string
	RunOnBoot bool
}

type Runner struct {
	cfg       RunnerConfig
	collector Collector
	analyzer  Analyzer
	journal   *Journal
	mu        sync.RWMutex
	last      *Snapshot
	latest    *Report
}

func NewRunner(cfg RunnerConfig) *Runner {
	if cfg.Interval <= 0 { cfg.Interval = time.Hour }
	if cfg.Timeout <= 0 { cfg.Timeout = 30 * time.Second }
	if cfg.Journal == "" { cfg.Journal = "outpost-journal.jsonl" }
	return &Runner{
		cfg: cfg,
		collector: NewLocalCollector(),
		analyzer: NewHeuristicAnalyzer(),
		journal: NewJournal(cfg.Journal),
	}
}

func (r *Runner) Run(ctx context.Context) error {
	if r.cfg.RunOnBoot {
		if _, err := r.RunOnce(ctx); err != nil { slog.Warn("initial patrol failed", "error", err) }
	}
	ticker := time.NewTicker(r.cfg.Interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done(): return nil
		case <-ticker.C:
			if _, err := r.RunOnce(ctx); err != nil { slog.Warn("scheduled patrol failed", "error", err) }
		}
	}
}

func (r *Runner) RunOnce(parent context.Context) (Report, error) {
	ctx, cancel := context.WithTimeout(parent, r.cfg.Timeout)
	defer cancel()
	started := time.Now()
	current := r.collector.Collect(ctx)

	r.mu.RLock()
	prev := r.last
	r.mu.RUnlock()
	checks, assessment, next, status := r.analyzer.Analyze(current, prev)
	report := Report{
		ID: fmt.Sprintf("%d", started.UnixNano()), Target: current.Target,
		StartedAt: started, FinishedAt: time.Now(), Status: status,
		Checks: checks, Assessment: assessment, Next: next,
	}
	if err := r.journal.Append(report); err != nil { return report, err }

	r.mu.Lock()
	r.last = &current
	r.latest = &report
	r.mu.Unlock()
	slog.Info("patrol completed", "target", report.Target, "status", report.Status, "checks", len(report.Checks))
	return report, nil
}

func (r *Runner) Latest() *Report {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.latest == nil { return nil }
	copy := *r.latest
	return &copy
}

func (r *Runner) Recent(limit int) ([]Report, error) { return r.journal.Recent(limit) }
