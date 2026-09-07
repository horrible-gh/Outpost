package patrol

import (
	"context"
	"errors"
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
	cfg      RunnerConfig
	journal  *Journal
	mu       sync.RWMutex
	latest   *PatrolReport
	previous *Snapshot
	sequence int64
}

func NewRunner(cfg RunnerConfig) *Runner {
	r := &Runner{
		cfg:     cfg,
		journal: NewJournal(cfg.Journal),
	}
	if recent, err := r.journal.Recent(1); err == nil && len(recent) == 1 {
		report := recent[0]
		r.latest = &report
		snapshot := report.Snapshot
		r.previous = &snapshot
		r.sequence = snapshot.Sequence
	}
	return r
}

func (r *Runner) Run(ctx context.Context) error {
	if r.cfg.Interval <= 0 {
		return errors.New("patrol interval must be greater than zero")
	}
	if r.cfg.Timeout <= 0 {
		return errors.New("patrol timeout must be greater than zero")
	}

	if r.cfg.RunOnBoot {
		if _, err := r.RunOnce(ctx); err != nil {
			slog.Warn("initial patrol failed", "error", err)
		}
	}

	ticker := time.NewTicker(r.cfg.Interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			if _, err := r.RunOnce(ctx); err != nil {
				slog.Warn("scheduled patrol failed", "error", err)
			}
		}
	}
}

func (r *Runner) RunOnce(parent context.Context) (PatrolReport, error) {
	ctx, cancel := context.WithTimeout(parent, r.cfg.Timeout)
	defer cancel()

	r.mu.RLock()
	previous := r.previous
	sequence := r.sequence + 1
	r.mu.RUnlock()

	snapshot := CollectLocal(ctx)
	snapshot.Sequence = sequence
	assessment := Analyze(snapshot, previous)
	report := PatrolReport{
		Snapshot:   snapshot,
		Assessment: assessment,
		Baseline:   previous == nil,
	}

	if err := r.journal.Append(report); err != nil {
		return report, err
	}

	r.mu.Lock()
	r.latest = &report
	copySnapshot := snapshot
	r.previous = &copySnapshot
	r.sequence = sequence
	r.mu.Unlock()

	slog.Info("patrol completed", "sequence", sequence, "target", snapshot.Target, "status", assessment.Status, "baseline", report.Baseline)
	return report, nil
}

func (r *Runner) Latest() *PatrolReport {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.latest == nil {
		return nil
	}
	copyReport := *r.latest
	return &copyReport
}
