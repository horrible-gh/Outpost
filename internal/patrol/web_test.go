package patrol

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestWebIndexRendersPatrolStatus(t *testing.T) {
	runner := NewRunner(RunnerConfig{Journal: t.TempDir() + "/journal.jsonl"})
	runner.latest = &PatrolReport{
		Snapshot: Snapshot{
			Sequence:  1,
			Target:    "test-host",
			OS:        "linux",
			StartedAt: time.Date(2026, 9, 8, 7, 0, 0, 0, time.UTC),
			Checks: []CheckResult{
				{Name: "Disk", Status: StatusNormal, Summary: "collected"},
			},
		},
		Assessment: Assessment{
			Status:  StatusNormal,
			Summary: "baseline ok",
			Changes: []string{"Baseline established from the first patrol."},
			Next:    []string{"Compare the next patrol with this baseline."},
		},
		Baseline: true,
	}

	server := NewWebServer("127.0.0.1:0", runner)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	server.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	for _, want := range []string{"test-host", "NORMAL", "BASELINE", "Disk"} {
		if !strings.Contains(body, want) {
			t.Fatalf("expected rendered page to contain %q", want)
		}
	}
}
