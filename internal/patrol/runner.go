package patrol

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"time"
)

type RunnerConfig struct {
	Interval           time.Duration
	Timeout            time.Duration
	Journal            string
	MarkdownJournalDir string
	RunOnBoot          bool
}

type Runner struct {
	cfg          RunnerConfig
	journal      *Journal
	agentJournal *AgentJournalStore
	runMu        sync.Mutex
	mu           sync.RWMutex
	latest       *PatrolReport
	previous     *Snapshot
	sequence     int64
}

func NewRunner(cfg RunnerConfig) *Runner {
	mdDir := cfg.MarkdownJournalDir
	if mdDir == "" {
		mdDir = cfg.Journal + "-md"
	}
	r := &Runner{
		cfg:          cfg,
		journal:      NewJournal(cfg.Journal),
		agentJournal: NewAgentJournalStore(mdDir),
	}
	if err := r.journal.NormalizeSequences(); err != nil {
		slog.Warn("journal sequence normalization failed", "error", err)
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
	r.runMu.Lock()
	defer r.runMu.Unlock()

	ctx, cancel := context.WithTimeout(parent, r.cfg.Timeout)
	defer cancel()

	r.mu.RLock()
	previous := r.previous
	sequence := r.sequence + 1
	r.mu.RUnlock()

	snapshot := CollectLocal(ctx)
	RefineSnapshot(ctx, &snapshot)
	snapshot.Sequence = sequence
	assessment := Analyze(snapshot, previous)
	report := PatrolReport{Snapshot: snapshot, Assessment: assessment, Baseline: previous == nil}
	if err := r.journal.Append(report); err != nil {
		return report, err
	}

	r.mu.Lock()
	r.latest = &report
	copySnapshot := snapshot
	r.previous = &copySnapshot
	r.sequence = sequence
	r.mu.Unlock()

	slog.Info("patrol completed", "sequence", sequence, "target", snapshot.Target, "status", assessment.Status, "risk", assessment.RiskScore, "baseline", report.Baseline)
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

func (r *Runner) Recent(limit int) ([]PatrolReport, error) {
	return r.journal.Recent(limit)
}

func (r *Runner) AgentJournalDir() string {
	return r.agentJournal.Dir()
}

func (r *Runner) AgentJournals(limit int) ([]AgentJournalEntry, error) {
	return r.agentJournal.List(limit)
}

func (r *Runner) AgentJournal(id string) (AgentJournalEntry, error) {
	return r.agentJournal.Get(id)
}

func (r *Runner) AppendAgentJournal(req AgentJournalWriteRequest) (AgentJournalEntry, error) {
	if req.PatrolSequence <= 0 {
		r.mu.RLock()
		if r.latest != nil {
			req.PatrolSequence = r.latest.Snapshot.Sequence
		}
		r.mu.RUnlock()
	}
	return r.agentJournal.Append(req)
}

func (r *Runner) AutonomousContext(patrolLimit, journalLimit int) (AutonomousPatrolContext, error) {
	if patrolLimit <= 0 {
		patrolLimit = 8
	}
	if patrolLimit > 50 {
		patrolLimit = 50
	}
	if journalLimit <= 0 {
		journalLimit = 6
	}
	if journalLimit > 30 {
		journalLimit = 30
	}
	history, err := r.Recent(patrolLimit)
	if err != nil {
		return AutonomousPatrolContext{}, err
	}
	journals, err := r.AgentJournals(journalLimit)
	if err != nil {
		return AutonomousPatrolContext{}, err
	}
	return BuildAutonomousPatrolContext(history, journals), nil
}
