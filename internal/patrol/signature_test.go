package patrol

import (
	"strings"
	"testing"
)

func TestAnalyzeIncludesAuthenticodeStatus(t *testing.T) {
	current := Snapshot{Checks: []CheckResult{
		{Key: "processes", Status: StatusNormal, Raw: `[{"Name":"odd.exe","ProcessId":10,"ExecutablePath":"C:\\Users\\u\\Downloads\\odd.exe"}]`},
		{Key: "process_signatures", Status: StatusNormal, Raw: `[{"Path":"C:\\Users\\u\\Downloads\\odd.exe","Status":"Valid","Signer":"CN=Example Corp"}]`},
	}}
	got := Analyze(current, nil)
	if len(got.Findings) == 0 { t.Fatal("expected finding") }
	message := got.Findings[0].Message
	if !strings.Contains(message, "Valid") || !strings.Contains(message, "Example Corp") {
		t.Fatalf("expected signature detail, got %q", message)
	}
}
