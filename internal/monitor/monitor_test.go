package monitor

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
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
	if result.BodySHA256 == "" || len(result.OpenPorts) == 0 {
		t.Fatalf("expected security surface evidence, got %+v", result)
	}
}

func TestRunnerPersistsTargets(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "services.json")
	runner := NewRunner(RunnerConfig{ConfigPath: configPath, Interval: time.Minute, Timeout: 3 * time.Second})
	created, err := runner.AddTarget(Target{Name: "Example", URL: "https://example.com"})
	if err != nil {
		t.Fatalf("add target: %v", err)
	}
	if created.ID == "" || !created.Enabled || created.ExpectedStatus != http.StatusOK {
		t.Fatalf("unexpected target defaults: %+v", created)
	}

	reloaded := NewRunner(RunnerConfig{ConfigPath: configPath, Interval: time.Minute, Timeout: 3 * time.Second})
	targets := reloaded.Targets()
	if len(targets) != 1 || targets[0].ID != created.ID || targets[0].URL != created.URL {
		t.Fatalf("target did not persist: %+v", targets)
	}
}

func TestCompareSurfaceDetectsMeaningfulChanges(t *testing.T) {
	before := SurfaceBaseline{
		DNSAddresses:   []string{"192.0.2.10"},
		TLSFingerprint: "aaa",
		TLSIssuer:      "issuer-a",
		BodySHA256:     "body-a",
		OpenPorts:      []int{80, 443},
	}
	after := SurfaceBaseline{
		DNSAddresses:   []string{"192.0.2.20"},
		TLSFingerprint: "bbb",
		TLSIssuer:      "issuer-b",
		BodySHA256:     "body-b",
		OpenPorts:      []int{443, 8080},
	}

	changes := compareSurface(before, after)
	joined := strings.Join(changes, " | ")
	for _, want := range []string{
		"DNS changed",
		"TLS certificate fingerprint changed",
		"TLS certificate issuer changed",
		"response body fingerprint changed",
		"new exposed port 8080",
		"port 80 is no longer exposed",
	} {
		if !strings.Contains(joined, want) {
			t.Fatalf("expected %q in changes: %v", want, changes)
		}
	}
}
