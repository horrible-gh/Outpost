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
	if got.Status != StatusNormal { t.Fatalf("expected normal, got %s", got.Status) }
	if len(got.Changes) != 1 || got.Changes[0] != "No meaningful security or health change detected since the previous patrol." { t.Fatalf("unexpected changes: %#v", got.Changes) }
}

func TestAnalyzeWarnsOnNewListener(t *testing.T) {
	previous := Snapshot{Checks: []CheckResult{{Key: "network", Status: StatusNormal, Raw: `[{"State":2,"LocalAddress":"0.0.0.0","LocalPort":80}]`}}}
	current := Snapshot{Checks: []CheckResult{{Key: "network", Status: StatusNormal, Raw: `[{"State":2,"LocalAddress":"0.0.0.0","LocalPort":80},{"State":2,"LocalAddress":"0.0.0.0","LocalPort":9000}]`}}}
	got := Analyze(current, &previous)
	if got.Status != StatusWarning { t.Fatalf("expected warning, got %s", got.Status) }
	if got.Watch.NewListeners != 1 { t.Fatalf("expected one new listener, got %d", got.Watch.NewListeners) }
}

func TestAnalyzeWarnsOnFailedLoginEvents(t *testing.T) {
	current := Snapshot{Checks: []CheckResult{{Key: "failed_logins", Status: StatusNormal, Raw: `[{"Id":4625}]`}}}
	got := Analyze(current, nil)
	if got.Status != StatusWarning { t.Fatalf("expected warning, got %s", got.Status) }
	if got.Watch.FailedLogins != 1 { t.Fatalf("expected one failed login, got %d", got.Watch.FailedLogins) }
}

func TestAnalyzeWarnsOnNewUserAndService(t *testing.T) {
	previous := Snapshot{Checks: []CheckResult{
		{Key: "users", Status: StatusNormal, Raw: `[{"Name":"admin"}]`},
		{Key: "services", Status: StatusNormal, Raw: `[{"Name":"known-service"}]`},
	}}
	current := Snapshot{Checks: []CheckResult{
		{Key: "users", Status: StatusNormal, Raw: `[{"Name":"admin"},{"Name":"unexpected"}]`},
		{Key: "services", Status: StatusNormal, Raw: `[{"Name":"known-service"},{"Name":"new-service"}]`},
	}}
	got := Analyze(current, &previous)
	if got.Status != StatusWarning { t.Fatalf("expected warning, got %s", got.Status) }
	if got.Watch.NewUsers != 1 || got.Watch.NewServices != 1 { t.Fatalf("unexpected watch summary: %#v", got.Watch) }
}

func TestAnalyzeWarnsOnSuspiciousProcessPath(t *testing.T) {
	current := Snapshot{Checks: []CheckResult{{Key: "processes", Status: StatusNormal, Raw: `[{"Name":"odd.exe","ProcessId":10,"ExecutablePath":"C:\\Users\\u\\Downloads\\odd.exe"}]`}}}
	got := Analyze(current, nil)
	if got.Status != StatusWarning { t.Fatalf("expected warning, got %s", got.Status) }
	if got.Watch.SuspiciousProcesses != 1 { t.Fatalf("expected one suspicious process, got %d", got.Watch.SuspiciousProcesses) }
}
