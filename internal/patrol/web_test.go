package patrol

import (
	"encoding/json"
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
		"markdown":"# Autonomous follow-up\n\nRead-only investigation completed."
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

	detail := httptest.NewRequest(http.MethodGet, "/api/journals/"+extractJSONID(t, postRec.Body.Bytes()), nil)
	detailRec := httptest.NewRecorder()
	handler.ServeHTTP(detailRec, detail)
	if detailRec.Code != http.StatusOK || !strings.Contains(detailRec.Body.String(), "<h1>Autonomous follow-up</h1>") {
		t.Fatalf("expected rendered journal detail, got %d: %s", detailRec.Code, detailRec.Body.String())
	}

	directive := httptest.NewRequest(http.MethodPost, "/api/journals", strings.NewReader(`{
		"kind":"directive",
		"author":"user",
		"title":"Inspect Docker logs",
		"summary":"Focus on Docker log growth and rotation.",
		"markdown":"Check Docker log growth, rotation, and follow anything suspicious."
	}`))
	directive.Header.Set("Content-Type", "application/json")
	directiveRec := httptest.NewRecorder()
	handler.ServeHTTP(directiveRec, directive)
	if directiveRec.Code != http.StatusCreated {
		t.Fatalf("expected directive create 201, got %d: %s", directiveRec.Code, directiveRec.Body.String())
	}
	if strings.Contains(directiveRec.Body.String(), `"patrol_sequence":7`) {
		t.Fatalf("future patrol brief must not attach to the previous patrol: %s", directiveRec.Body.String())
	}

	list := httptest.NewRequest(http.MethodGet, "/api/journals", nil)
	listRec := httptest.NewRecorder()
	handler.ServeHTTP(listRec, list)
	if listRec.Code != http.StatusOK || !strings.Contains(listRec.Body.String(), "Autonomous follow-up") || !strings.Contains(listRec.Body.String(), "Inspect Docker logs") {
		t.Fatalf("expected journal/directive list, got %d: %s", listRec.Code, listRec.Body.String())
	}

	contextReq := httptest.NewRequest(http.MethodGet, "/api/agent/context", nil)
	contextRec := httptest.NewRecorder()
	handler.ServeHTTP(contextRec, contextReq)
	if contextRec.Code != http.StatusOK {
		t.Fatalf("expected context 200, got %d: %s", contextRec.Code, contextRec.Body.String())
	}
	for _, want := range []string{"autonomous-read-only", "Autonomous follow-up", "Inspect Docker logs", "Check Docker log growth, rotation, and follow anything suspicious.", "primary_user_directive", "does not count as autonomous investigation", "Observe and investigate only"} {
		if !strings.Contains(contextRec.Body.String(), want) {
			t.Fatalf("expected agent context to contain %q: %s", want, contextRec.Body.String())
		}
	}
}


func TestAPIHelpDocumentsEveryRegisteredAPIRoute(t *testing.T) {
	dir := t.TempDir()
	runner := NewRunner(RunnerConfig{
		Interval:           time.Hour,
		Timeout:            30 * time.Second,
		Journal:            filepath.Join(dir, "journal.jsonl"),
		MarkdownJournalDir: filepath.Join(dir, "journals"),
	})
	server := NewWebServer("127.0.0.1:6877", runner)

	req := httptest.NewRequest(http.MethodGet, "/api/help", nil)
	rec := httptest.NewRecorder()
	server.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected help 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var help APIHelp
	if err := json.Unmarshal(rec.Body.Bytes(), &help); err != nil {
		t.Fatalf("decode help: %v", err)
	}
	if help.Entrypoint != "/api/help" {
		t.Fatalf("unexpected entrypoint %q", help.Entrypoint)
	}
	if help.Runtime.ListenAddress != "127.0.0.1:6877" {
		t.Fatalf("unexpected listen address %q", help.Runtime.ListenAddress)
	}
	if help.Runtime.PatrolInterval != "1h0m0s" || help.Runtime.PatrolTimeout != "30s" {
		t.Fatalf("unexpected patrol runtime: %#v", help.Runtime)
	}
	if help.Safety.TargetMutations {
		t.Fatalf("help must preserve read-only target policy")
	}

	got := map[string]bool{}
	for _, group := range help.EndpointGroups {
		for _, endpoint := range group.Endpoints {
			got[endpoint.Method+" "+endpoint.Path] = true
		}
	}
	want := []string{
		"GET /api/help",
		"GET /api/status",
		"GET /api/patrols",
		"GET /api/review-packet",
		"GET /api/agent/context",
		"GET /api/journals",
		"GET /api/journals/{id}",
		"POST /api/journals",
		"POST /api/patrols/run",
		"GET /api/services",
		"POST /api/services",
		"POST /api/services/run",
		"POST /api/services/{id}/run",
		"DELETE /api/services/{id}",
	}
	for _, route := range want {
		if !got[route] {
			t.Fatalf("help is missing registered route %q", route)
		}
	}
	if len(got) != len(want) {
		t.Fatalf("help route count drift: got %d, expected %d: %#v", len(got), len(want), got)
	}
}

func TestAPIHelpDocumentsAgentJournalContract(t *testing.T) {
	runner := NewRunner(RunnerConfig{Journal: filepath.Join(t.TempDir(), "journal.jsonl")})
	help := NewWebServer("127.0.0.1:0", runner).buildAPIHelp()

	var journal *APIHelpEndpoint
	for gi := range help.EndpointGroups {
		for ei := range help.EndpointGroups[gi].Endpoints {
			endpoint := &help.EndpointGroups[gi].Endpoints[ei]
			if endpoint.Method == "POST" && endpoint.Path == "/api/journals" {
				journal = endpoint
			}
		}
	}
	if journal == nil {
		t.Fatal("POST /api/journals missing from help")
	}
	if !journal.MutatesOutpost || !journal.TargetReadOnly {
		t.Fatalf("journal safety classification is wrong: %#v", journal)
	}
	required := map[string]bool{}
	for _, field := range journal.Body {
		if field.Required {
			required[field.Name] = true
		}
	}
	if !required["title"] || !required["markdown"] {
		t.Fatalf("journal required fields missing: %#v", required)
	}
	if journal.ExampleBody["markdown"] == nil {
		t.Fatalf("journal example body should include markdown")
	}
	fields := map[string]bool{}
	for _, field := range journal.Body {
		fields[field.Name] = true
	}
	if !fields["kind"] || !fields["author"] {
		t.Fatalf("journal help should document directive metadata: %#v", fields)
	}
}


func TestUnknownAPIPathReturnsNotFound(t *testing.T) {
	runner := NewRunner(RunnerConfig{Journal: filepath.Join(t.TempDir(), "journal.jsonl")})
	server := NewWebServer("127.0.0.1:0", runner)

	req := httptest.NewRequest(http.MethodGet, "/api/helpp", nil)
	rec := httptest.NewRecorder()
	server.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected unknown API path to return 404, got %d: %s", rec.Code, rec.Body.String())
	}
}


func TestWebIndexShowsPatrolBriefAndMarkdownViewer(t *testing.T) {
	dir := t.TempDir()
	runner := NewRunner(RunnerConfig{
		Journal:            filepath.Join(dir, "journal.jsonl"),
		MarkdownJournalDir: filepath.Join(dir, "journals"),
	})
	if _, err := runner.AppendAgentJournal(AgentJournalWriteRequest{
		Kind: "directive", Author: "user", Title: "Check DB backup lag",
		Summary: "Pay attention to backup lag.", Markdown: "Check **backup lag** and related errors.",
	}); err != nil {
		t.Fatalf("append directive: %v", err)
	}
	server := NewWebServer("127.0.0.1:0", runner)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	server.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected index 200, got %d: %s", rec.Code, rec.Body.String())
	}
	for _, want := range []string{"User Patrol Brief", "CURRENT BRIEF", "Check DB backup lag", "Rendered Markdown", "addPatrolBrief", "markdown-body"} {
		if !strings.Contains(rec.Body.String(), want) {
			t.Fatalf("expected index to contain %q", want)
		}
	}
}

func extractJSONID(t *testing.T, body []byte) string {
	t.Helper()
	var payload struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		t.Fatalf("decode id: %v", err)
	}
	if payload.ID == "" {
		t.Fatalf("missing id in %s", string(body))
	}
	return payload.ID
}
