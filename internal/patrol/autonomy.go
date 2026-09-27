package patrol

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

type PatrolDigest struct {
	Sequence      int64     `json:"sequence"`
	StartedAt     time.Time `json:"started_at"`
	Status        Status    `json:"status"`
	RiskScore     int       `json:"risk_score"`
	Summary       string    `json:"summary"`
	CPUPercent    float64   `json:"cpu_percent"`
	MemoryPercent float64   `json:"memory_percent"`
	SwapPercent   float64   `json:"swap_percent"`
}

type AttentionSignal struct {
	Kind     string   `json:"kind"`
	Level    string   `json:"level"`
	Message  string   `json:"message"`
	Evidence []string `json:"evidence,omitempty"`
}

type AutonomousPatrolContext struct {
	GeneratedAt        time.Time            `json:"generated_at"`
	Mode               string               `json:"mode"`
	DefaultDepthHint   string               `json:"default_depth_hint"`
	StablePatrolStreak int                  `json:"stable_patrol_streak"`
	LatestReview       *ReviewPacket        `json:"latest_review,omitempty"`
	RecentPatrols      []PatrolDigest       `json:"recent_patrols"`
	RecentJournals     []AgentJournalEntry  `json:"recent_journals"`
	UserDirectives     []AgentJournalEntry  `json:"user_directives"`
	PrimaryDirective   *AgentJournalEntry   `json:"primary_user_directive,omitempty"`
	MissionRules       []string             `json:"mission_rules"`
	Signals            []AttentionSignal    `json:"signals"`
	PendingChecks      []string             `json:"pending_checks"`
	Guardrails         []string             `json:"guardrails"`
	Workflow           []string             `json:"workflow"`
}

func BuildAutonomousPatrolContext(history []PatrolReport, journals []AgentJournalEntry, directives []AgentJournalEntry) AutonomousPatrolContext {
	ctx := AutonomousPatrolContext{
		GeneratedAt:      time.Now().UTC(),
		Mode:             "autonomous-read-only",
		DefaultDepthHint: "normal",
		Guardrails: []string{
			"Observe and investigate only; do not mutate the target host.",
			"Do not restart services, install packages, modify files, change accounts, or change firewall rules.",
			"Treat the depth hint as advisory. Follow stronger current evidence, explicit user directives, or unresolved journal items.",
			"Record why extra checks were chosen and why optional checks were skipped.",
		},
		MissionRules: []string{
			"If primary_user_directive exists, treat it as the primary patrol objective unless it conflicts with a safety guardrail.",
			"Outpost built-in patrol checks are baseline evidence. Merely repeating, paraphrasing, or re-running the same checks does not count as autonomous investigation.",
			"When useful and safe, perform at least one additional read-only check that is not already represented by the baseline patrol evidence.",
			"If no additional check is useful, explicitly explain why rather than pretending the baseline patrol itself was autonomous investigation.",
			"After satisfying the user directive, follow evidence-driven anomalies and recurring patterns as secondary objectives.",
		},
		Workflow: []string{
			"Read the newest user patrol directive first. Use older directives only as historical context when they do not conflict with the newest one.",
			"Run or inspect the current Outpost patrol only to establish baseline evidence and recent changes.",
			"Choose additional read-only checks that go beyond the baseline checklist and are justified by the directive, signals, patterns, or journal carry-over.",
			"Follow meaningful anomalies recursively within the read-only boundary.",
			"Finish by writing a Markdown patrol journal that records the user directive, chosen extra checks, rationale, findings, skipped checks, and next checks.",
		},
	}
	ctx.UserDirectives = prepareDirectiveContext(directives)
	if len(ctx.UserDirectives) > 0 {
		primary := ctx.UserDirectives[0]
		ctx.PrimaryDirective = &primary
		ctx.Signals = append(ctx.Signals, AttentionSignal{
			Kind: "user-directive", Level: "info",
			Message: fmt.Sprintf("Primary patrol objective from user: %s", primary.Title),
			Evidence: []string{primary.Preview},
		})
	}
	if len(history) == 0 {
		ctx.Signals = append(ctx.Signals, AttentionSignal{
			Kind: "baseline", Level: "info",
			Message: "No patrol history is available yet; establish a baseline before adapting patrol depth.",
		})
		ctx.RecentJournals = trimJournalBodies(journals)
		return ctx
	}

	for _, report := range history {
		ctx.RecentPatrols = append(ctx.RecentPatrols, PatrolDigest{
			Sequence:      report.Snapshot.Sequence,
			StartedAt:     report.Snapshot.StartedAt,
			Status:        report.Assessment.Status,
			RiskScore:     report.Assessment.RiskScore,
			Summary:       report.Assessment.Summary,
			CPUPercent:    report.Assessment.Health.CPUPercent,
			MemoryPercent: report.Assessment.Health.MemoryPercent,
			SwapPercent:   report.Assessment.Health.SwapPercent,
		})
	}
	latest := history[0]
	packet := BuildReviewPacket(latest)
	ctx.LatestReview = &packet
	ctx.PendingChecks = append(ctx.PendingChecks, latest.Assessment.Next...)

	for _, report := range history {
		if report.Assessment.Status != StatusNormal {
			break
		}
		ctx.StablePatrolStreak++
	}

	switch {
	case latest.Assessment.Status == StatusDanger || latest.Assessment.RiskScore >= 60:
		ctx.DefaultDepthHint = "deep"
	case latest.Assessment.Status == StatusWarning || latest.Assessment.RiskScore >= 30:
		ctx.DefaultDepthHint = "focused"
	case ctx.StablePatrolStreak >= 5:
		ctx.DefaultDepthHint = "light"
	}

	ctx.Signals = append(ctx.Signals, statusSignals(history, ctx.StablePatrolStreak)...)
	ctx.Signals = append(ctx.Signals, trendSignals(history)...)
	ctx.Signals = append(ctx.Signals, repeatedFindingSignals(history)...)

	for _, journal := range journals {
		ctx.PendingChecks = append(ctx.PendingChecks, journal.Next...)
		if journal.Status == "warning" || journal.Status == "danger" {
			ctx.Signals = append(ctx.Signals, AttentionSignal{
				Kind: "journal-carryover", Level: journal.Status,
				Message: fmt.Sprintf("Recent journal %q carries a %s state.", journal.Title, journal.Status),
				Evidence: append([]string(nil), journal.Focus...),
			})
		}
	}
	ctx.PendingChecks = cleanStrings(ctx.PendingChecks)
	ctx.RecentJournals = trimJournalBodies(journals)
	sort.SliceStable(ctx.Signals, func(i, j int) bool {
		return signalRank(ctx.Signals[i].Level) > signalRank(ctx.Signals[j].Level)
	})
	return ctx
}

func statusSignals(history []PatrolReport, stableStreak int) []AttentionSignal {
	latest := history[0]
	switch latest.Assessment.Status {
	case StatusDanger:
		return []AttentionSignal{{Kind: "current-status", Level: "danger", Message: "Latest patrol is in DANGER; deepen investigation around current findings."}}
	case StatusWarning:
		return []AttentionSignal{{Kind: "current-status", Level: "warning", Message: "Latest patrol is in WARNING; prioritize the warning findings before routine expansion."}}
	case StatusUnknown:
		return []AttentionSignal{{Kind: "current-status", Level: "warning", Message: "Latest patrol contains insufficient evidence; retry unavailable checks before assuming stability."}}
	default:
		if stableStreak >= 5 {
			return []AttentionSignal{{
				Kind: "stable-streak", Level: "info",
				Message: fmt.Sprintf("%d consecutive patrols are normal; routine depth may be reduced unless another signal or journal item needs follow-up.", stableStreak),
			}}
		}
	}
	return nil
}

func trendSignals(history []PatrolReport) []AttentionSignal {
	if len(history) < 2 {
		return nil
	}
	latest := history[0].Assessment
	oldest := history[len(history)-1].Assessment
	var signals []AttentionSignal

	if delta := latest.RiskScore - oldest.RiskScore; delta >= 15 {
		signals = append(signals, AttentionSignal{
			Kind: "risk-trend", Level: "warning",
			Message: fmt.Sprintf("Security risk rose by %d points across the review window.", delta),
			Evidence: []string{fmt.Sprintf("%d -> %d", oldest.RiskScore, latest.RiskScore)},
		})
	}
	if delta := latest.Health.MemoryPercent - oldest.Health.MemoryPercent; delta >= 10 {
		signals = append(signals, AttentionSignal{
			Kind: "memory-trend", Level: "warning",
			Message: fmt.Sprintf("Memory utilization rose %.1f percentage points across the review window.", delta),
		})
	}
	if delta := latest.Health.SwapPercent - oldest.Health.SwapPercent; delta >= 10 {
		signals = append(signals, AttentionSignal{
			Kind: "swap-trend", Level: "warning",
			Message: fmt.Sprintf("Swap/pagefile utilization rose %.1f percentage points across the review window.", delta),
		})
	}
	return signals
}

func repeatedFindingSignals(history []PatrolReport) []AttentionSignal {
	type categoryInfo struct {
		count   int
		level   string
		samples []string
	}
	counts := map[string]*categoryInfo{}
	for _, report := range history {
		seenInReport := map[string]struct{}{}
		for _, finding := range report.Assessment.Findings {
			category := strings.TrimSpace(finding.Category)
			if category == "" {
				continue
			}
			if _, seen := seenInReport[category]; seen {
				continue
			}
			seenInReport[category] = struct{}{}
			info := counts[category]
			if info == nil {
				info = &categoryInfo{level: "info"}
				counts[category] = info
			}
			info.count++
			if signalRank(string(finding.Severity)) > signalRank(info.level) {
				info.level = string(finding.Severity)
			}
			if len(info.samples) < 3 && finding.Message != "" {
				info.samples = append(info.samples, finding.Message)
			}
		}
	}
	var out []AttentionSignal
	for category, info := range counts {
		if info.count < 2 {
			continue
		}
		level := info.level
		if level == "normal" || level == "" {
			level = "info"
		}
		out = append(out, AttentionSignal{
			Kind: "repeated-" + category,
			Level: level,
			Message: fmt.Sprintf("Finding category %q appeared in %d recent patrols; treat it as a pattern worth rechecking.", category, info.count),
			Evidence: info.samples,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Kind < out[j].Kind })
	return out
}

func prepareDirectiveContext(directives []AgentJournalEntry) []AgentJournalEntry {
	out := make([]AgentJournalEntry, len(directives))
	for i, directive := range directives {
		if directive.Preview == "" {
			directive.Preview = markdownPreview(directive.Markdown, 360)
		}
		// User instructions are deliberately included with substantially more
		// context than ordinary journal previews so the patrol agent can execute
		// the actual brief rather than infer it from a short summary.
		runes := []rune(directive.Markdown)
		if len(runes) > 4000 {
			directive.Markdown = string(runes[:4000]) + "\n\n[brief truncated by Outpost]"
		}
		directive.HTML = ""
		out[i] = directive
	}
	return out
}

func trimJournalBodies(journals []AgentJournalEntry) []AgentJournalEntry {
	out := make([]AgentJournalEntry, len(journals))
	for i, journal := range journals {
		if journal.Preview == "" {
			journal.Preview = markdownPreview(journal.Markdown, 360)
		}
		journal.Markdown = ""
		out[i] = journal
	}
	return out
}

func signalRank(level string) int {
	switch strings.ToLower(level) {
	case "danger":
		return 4
	case "warning":
		return 3
	case "unknown":
		return 2
	case "info", "note", "normal":
		return 1
	default:
		return 0
	}
}
