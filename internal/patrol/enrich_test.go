package patrol

import (
	"strings"
	"testing"
)

func TestAnalyzeShowsSuspiciousProcessPath(t *testing.T) {
	current := Snapshot{Checks: []CheckResult{
		{Key: "processes", Status: StatusNormal, Raw: `[{"Name":"odd.exe","ProcessId":10,"ExecutablePath":"C:\\Users\\u\\Downloads\\odd.exe"}]`},
	}}
	got := Analyze(current, nil)
	if got.Status != StatusWarning { t.Fatalf("expected warning, got %s", got.Status) }
	if len(got.Findings) == 0 { t.Fatal("expected findings") }
	if !strings.Contains(got.Findings[0].Message, "odd.exe") || !strings.Contains(got.Findings[0].Message, "Downloads") {
		t.Fatalf("expected concrete process detail, got %#v", got.Findings)
	}
	if !strings.Contains(got.Summary, "odd.exe") {
		t.Fatalf("expected concrete summary, got %q", got.Summary)
	}
}
