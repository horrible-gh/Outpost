package patrol

import "testing"

func TestAnalyzeIgnoresRoutineRawChanges(t *testing.T) {
	previous := Snapshot{Checks: []CheckResult{
		{Key: "disk", Status: StatusNormal, Raw: `{"DeviceID":"C:","Size":1000,"FreeSpace":800}`},
		{Key: "network", Status: StatusNormal, Raw: `[{"State":2,"LocalAddress":"0.0.0.0","LocalPort":80}]`},
		{Key: "failed_logins", Status: StatusNormal, Raw: `[]`},
	}}
	current := Snapshot{Checks: []CheckResult{
		{Key: "disk", Status: StatusNormal, Raw: `{"DeviceID":"C:","Size":1000,"FreeSpace":799}`},
		{Key: "network", Status: StatusNormal, Raw: `[{"State":2,"LocalAddress":"0.0.0.0","LocalPort":80}]`},
		{Key: "failed_logins", Status: StatusNormal, Raw: `[]`},
	}}

	got := Analyze(current, &previous)
	if got.Status != StatusNormal {
		t.Fatalf("expected normal, got %s", got.Status)
	}
	if len(got.Changes) != 1 || got.Changes[0] != "No meaningful security or health change detected since the previous patrol." {
		t.Fatalf("unexpected changes: %#v", got.Changes)
	}
}

func TestAnalyzeWarnsOnNewListener(t *testing.T) {
	previous := Snapshot{Checks: []CheckResult{
		{Key: "network", Status: StatusNormal, Raw: `[{"State":2,"LocalAddress":"0.0.0.0","LocalPort":80}]`},
	}}
	current := Snapshot{Checks: []CheckResult{
		{Key: "network", Status: StatusNormal, Raw: `[{"State":2,"LocalAddress":"0.0.0.0","LocalPort":80},{"State":2,"LocalAddress":"0.0.0.0","LocalPort":9000}]`},
	}}

	got := Analyze(current, &previous)
	if got.Status != StatusWarning {
		t.Fatalf("expected warning, got %s", got.Status)
	}
}

func TestAnalyzeWarnsOnFailedLoginEvents(t *testing.T) {
	current := Snapshot{Checks: []CheckResult{
		{Key: "failed_logins", Status: StatusNormal, Raw: `[{"Id":4625}]`},
	}}

	got := Analyze(current, nil)
	if got.Status != StatusWarning {
		t.Fatalf("expected warning, got %s", got.Status)
	}
}
