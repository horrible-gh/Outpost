package monitor

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"
)

func TestCheckTargetHTTP(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("healthy"))
	}))
	defer server.Close()

	result := checkTarget(context.Background(), Target{
		ID:             "svc-test",
		Name:           "test service",
		URL:            server.URL,
		ExpectedStatus: http.StatusOK,
		MaxLatencyMS:   5000,
		BodyContains:   "healthy",
		Enabled:        true,
	})

	if result.Status != StatusUp {
		t.Fatalf("expected service to be up, got %s: %s (%s)", result.Status, result.Summary, result.Error)
	}
	if !result.TCPReachable || result.HTTPStatus != http.StatusOK || !result.ContentMatched {
		t.Fatalf("unexpected result: %+v", result)
	}
}

func TestRunnerPersistsTargets(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "services.json")
	runner := NewRunner(RunnerConfig{ConfigPath: configPath, Interval: time.Minute, Timeout: time.Second})
	created, err := runner.AddTarget(Target{Name: "Example", URL: "https://example.com"})
	if err != nil {
		t.Fatalf("add target: %v", err)
	}
	if created.ID == "" || !created.Enabled || created.ExpectedStatus != http.StatusOK {
		t.Fatalf("unexpected target defaults: %+v", created)
	}

	reloaded := NewRunner(RunnerConfig{ConfigPath: configPath, Interval: time.Minute, Timeout: time.Second})
	targets := reloaded.Targets()
	if len(targets) != 1 || targets[0].ID != created.ID || targets[0].URL != created.URL {
		t.Fatalf("target did not persist: %+v", targets)
	}
}
