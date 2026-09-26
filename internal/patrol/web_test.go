package patrol

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
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


func TestWebAgentJournalAndContextAPI(t *testing.T) {
	dir := t.TempDir()
	runner := NewRunner(RunnerConfig{
		Journal:            filepath.Join(dir, "journal.jsonl"),
		MarkdownJournalDir: filepath.Join(dir, "journals"),
	})
	runner.latest = &PatrolReport{
		Snapshot: Snapshot{Sequence: 7, Target: "test-host", OS: "linux", StartedAt: time.Now()},
		Assessment: Assessment{Status: StatusNormal, Summary: "stable"},
	}
	runner.sequence = 7

	server := NewWebServer("127.0.0.1:0", runner)
	handler := server.Handler()

	post := httptest.NewRequest(http.MethodPost, "/api/journals", strings.NewReader(`{
		"title":"Autonomous follow-up",
		"status":"note",
		"summary":"Checked a suspicious trend.",
		"markdown":"# Autonomous follow-up\\n\\nRead-only investigation completed."
	}`))
	post.Header.Set("Content-Type", "application/json")
	postRec := httptest.NewRecorder()
	handler.ServeHTTP(postRec, post)
	if postRec.Code != http.StatusCreated {
		t.Fatalf("expected journal create 201, got %d: %s", postRec.Code, postRec.Body.String())
	}
	if !strings.Contains(postRec.Body.String(), `"patrol_sequence":7`) {
		t.Fatalf("expected latest patrol sequence to be attached: %s", postRec.Body.String())
	}

	list := httptest.NewRequest(http.MethodGet, "/api/journals", nil)
	listRec := httptest.NewRecorder()
	handler.ServeHTTP(listRec, list)
	if listRec.Code != http.StatusOK || !strings.Contains(listRec.Body.String(), "Autonomous follow-up") {
		t.Fatalf("expected journal list, got %d: %s", listRec.Code, listRec.Body.String())
	}

	contextReq := httptest.NewRequest(http.MethodGet, "/api/agent/context", nil)
	contextRec := httptest.NewRecorder()
	handler.ServeHTTP(contextRec, contextReq)
	if contextRec.Code != http.StatusOK {
		t.Fatalf("expected context 200, got %d: %s", contextRec.Code, contextRec.Body.String())
	}
	for _, want := range []string{"autonomous-read-only", "Autonomous follow-up", "Observe and investigate only"} {
		if !strings.Contains(contextRec.Body.String(), want) {
			t.Fatalf("expected agent context to contain %q: %s", want, contextRec.Body.String())
		}
	}
}
