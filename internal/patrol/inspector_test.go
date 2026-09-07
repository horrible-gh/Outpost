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
	if got.RiskScore != 0 { t.Fatalf("expected risk 0, got %d", got.RiskScore) }
	if len(got.Changes) != 1 || got.Changes[0] != "No meaningful security or health change detected since the previous patrol." { t.Fatalf("unexpected changes: %#v", got.Changes) }
}

func TestAnalyzeWarnsOnNewListener(t *testing.T) {
	previous := Snapshot{Checks: []CheckResult{{Key: "network", Status: StatusNormal, Raw: `[{"State":2,"LocalAddress":"0.0.0.0","LocalPort":80}]`}}}
	current := Snapshot{Checks: []CheckResult{{Key: "network", Status: StatusNormal, Raw: `[{"State":2,"LocalAddress":"0.0.0.0","LocalPort":80},{"State":2,"LocalAddress":"0.0.0.0","LocalPort":9000}]`}}}
	got := Analyze(current, &previous)
	if got.Status != StatusWarning { t.Fatalf("expected warning, got %s", got.Status) }
	if got.Watch.NewListeners != 1 || got.RiskScore != 10 { t.Fatalf("unexpected result: %#v", got.Assessment) }
}

func TestAnalyzeWarnsOnFailedLoginEvents(t *testing.T) {
	current := Snapshot{Checks: []CheckResult{{Key: "failed_logins", Status: StatusNormal, Raw: `[{"Id":4625}]`}}}
	got := Analyze(current, nil)
	if got.Status != StatusWarning { t.Fatalf("expected warning, got %s", got.Status) }
	if got.Watch.FailedLogins != 1 || got.RiskScore != 2 { t.Fatalf("unexpected watch/risk: %#v %d", got.Watch, got.RiskScore) }
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
	if got.Watch.NewUsers != 1 || got.Watch.NewServices != 1 || got.RiskScore != 30 { t.Fatalf("unexpected result: %#v risk=%d", got.Watch, got.RiskScore) }
}

func TestAnalyzeWarnsOnSuspiciousProcessPath(t *testing.T) {
	current := Snapshot{Checks: []CheckResult{{Key: "processes", Status: StatusNormal, Raw: `[{"Name":"odd.exe","ProcessId":10,"ExecutablePath":"C:\\Users\\u\\Downloads\\odd.exe"}]`}}}
	got := Analyze(current, nil)
	if got.Status != StatusWarning { t.Fatalf("expected warning, got %s", got.Status) }
	if got.Watch.SuspiciousProcesses != 1 || got.RiskScore != 20 { t.Fatalf("unexpected result: %#v risk=%d", got.Watch, got.RiskScore) }
}

func TestAnalyzeDangerWhenDefenderProtectionDisabled(t *testing.T) {
	current := Snapshot{Checks: []CheckResult{{Key: "defender_status", Status: StatusNormal, Raw: `{"AntivirusEnabled":true,"AntispywareEnabled":true,"RealTimeProtectionEnabled":false,"BehaviorMonitorEnabled":true}`}}}
	got := Analyze(current, nil)
	if got.Status != StatusDanger { t.Fatalf("expected danger, got %s", got.Status) }
	if got.Watch.ProtectionIssues != 1 || got.RiskScore != 25 { t.Fatalf("unexpected result: %#v risk=%d", got.Watch, got.RiskScore) }
	if len(got.Findings) == 0 || got.Findings[0].Category != "protection" { t.Fatalf("expected protection finding, got %#v", got.Findings) }
}

func TestAnalyzeWarnsOnDefenderThreat(t *testing.T) {
	current := Snapshot{Checks: []CheckResult{{Key: "defender_threats", Status: StatusNormal, Raw: `[{"ThreatID":123}]`}}}
	got := Analyze(current, nil)
	if got.Status != StatusWarning { t.Fatalf("expected warning, got %s", got.Status) }
	if got.Watch.ThreatDetections != 1 || got.RiskScore != 30 { t.Fatalf("unexpected result: %#v risk=%d", got.Watch, got.RiskScore) }
}
