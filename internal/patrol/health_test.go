package patrol

import "testing"

func TestSystemHealthNormal(t *testing.T) {
	current := Snapshot{Checks: []CheckResult{{Key: "system_health", Status: StatusNormal, Raw: `{"CPUPercent":25.0,"MemoryPercent":55.0,"SwapPercent":10.0}`}}}
	got := Analyze(current, nil)
	if got.Status != StatusNormal { t.Fatalf("expected normal, got %s", got.Status) }
	if got.Health.CPUPercent != 25 || got.Health.MemoryPercent != 55 || got.Health.SwapPercent != 10 { t.Fatalf("unexpected health: %#v", got.Health) }
}

func TestSystemHealthWarningThreshold(t *testing.T) {
	current := Snapshot{Checks: []CheckResult{{Key: "system_health", Status: StatusNormal, Raw: `{"CPUPercent":86.0,"MemoryPercent":40.0,"SwapPercent":5.0}`}}}
	got := Analyze(current, nil)
	if got.Status != StatusWarning { t.Fatalf("expected warning, got %s", got.Status) }
}

func TestSystemHealthDangerThreshold(t *testing.T) {
	current := Snapshot{Checks: []CheckResult{{Key: "system_health", Status: StatusNormal, Raw: `{"CPUPercent":20.0,"MemoryPercent":96.0,"SwapPercent":5.0}`}}}
	got := Analyze(current, nil)
	if got.Status != StatusDanger { t.Fatalf("expected danger, got %s", got.Status) }
}

func TestSystemHealthSwapWarning(t *testing.T) {
	current := Snapshot{Checks: []CheckResult{{Key: "system_health", Status: StatusNormal, Raw: `{"CPUPercent":20.0,"MemoryPercent":60.0,"SwapPercent":75.0}`}}}
	got := Analyze(current, nil)
	if got.Status != StatusWarning { t.Fatalf("expected warning, got %s", got.Status) }
}
