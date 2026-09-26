package patrol

import (
	"strings"
	"testing"
	"time"
)

func TestAutonomousContextReducesDepthAfterStableStreak(t *testing.T) {
	var history []PatrolReport
	for seq := int64(5); seq >= 1; seq-- {
		history = append(history, PatrolReport{
			Snapshot: Snapshot{Sequence: seq, StartedAt: time.Unix(seq, 0)},
			Assessment: Assessment{
				Status: StatusNormal,
				Summary: "stable",
				Health: HealthSummary{MemoryPercent: 40},
				Next: []string{"Continue scheduled patrols."},
			},
		})
	}
	ctx := BuildAutonomousPatrolContext(history, nil)
	if ctx.DefaultDepthHint != "light" {
		t.Fatalf("expected light depth, got %q", ctx.DefaultDepthHint)
	}
	if ctx.StablePatrolStreak != 5 {
		t.Fatalf("expected stable streak 5, got %d", ctx.StablePatrolStreak)
	}
	found := false
	for _, signal := range ctx.Signals {
		if signal.Kind == "stable-streak" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected stable-streak signal: %#v", ctx.Signals)
	}
}

func TestAutonomousContextSurfacesRepeatedPatternAndJournalCarryover(t *testing.T) {
	history := []PatrolReport{
		{
			Snapshot: Snapshot{Sequence: 3, StartedAt: time.Now()},
			Assessment: Assessment{
				Status: StatusWarning,
				RiskScore: 35,
				Summary: "warning",
				Findings: []Finding{{Category: "exposure", Severity: StatusWarning, Message: "new listener"}},
				Next: []string{"Recheck listener."},
			},
		},
		{
			Snapshot: Snapshot{Sequence: 2, StartedAt: time.Now().Add(-time.Hour)},
			Assessment: Assessment{
				Status: StatusWarning,
				RiskScore: 20,
				Summary: "warning",
				Findings: []Finding{{Category: "exposure", Severity: StatusWarning, Message: "listener changed"}},
			},
		},
	}
	journals := []AgentJournalEntry{{
		ID: "j1", Status: "warning", Title: "Port follow-up",
		Focus: []string{"listener 8443"}, Next: []string{"Confirm owner process."},
		Markdown: "# note\nfull body",
	}}
	ctx := BuildAutonomousPatrolContext(history, journals)
	if ctx.DefaultDepthHint != "focused" {
		t.Fatalf("expected focused depth, got %q", ctx.DefaultDepthHint)
	}
	if len(ctx.RecentJournals) != 1 || ctx.RecentJournals[0].Markdown != "" {
		t.Fatalf("context should carry journal metadata/preview without full markdown: %#v", ctx.RecentJournals)
	}
	if !containsString(ctx.PendingChecks, "Confirm owner process.") {
		t.Fatalf("missing journal carryover: %#v", ctx.PendingChecks)
	}
	var repeated bool
	for _, signal := range ctx.Signals {
		if strings.HasPrefix(signal.Kind, "repeated-exposure") {
			repeated = true
		}
	}
	if !repeated {
		t.Fatalf("expected repeated exposure signal: %#v", ctx.Signals)
	}
}

func containsString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}
