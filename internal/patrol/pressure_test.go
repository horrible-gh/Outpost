package patrol

import "testing"

func TestWindowsResourceHeavyProcessDetected(t *testing.T) {
	current := Snapshot{Checks: []CheckResult{{Key: "process_pressure", Status: StatusNormal, Raw: `[{"Name":"busy","ProcessId":42,"CPUPercent":94.0,"MemoryPercent":3.0},{"Name":"normal","ProcessId":43,"CPUPercent":5.0,"MemoryPercent":2.0}]`}}}
	got := Analyze(current, nil)
	if got.Status != StatusWarning { t.Fatalf("expected warning, got %s", got.Status) }
	if got.Watch.ResourceHeavyProcesses != 1 { t.Fatalf("expected one heavy process, got %d", got.Watch.ResourceHeavyProcesses) }
}

func TestLinuxResourceHeavyProcessDetected(t *testing.T) {
	current := Snapshot{Checks: []CheckResult{{Key: "process_pressure", Status: StatusNormal, Raw: "42 busy-worker 92.5 5.0\n43 normal 3.0 1.0"}}}
	got := Analyze(current, nil)
	if got.Status != StatusWarning { t.Fatalf("expected warning, got %s", got.Status) }
	if got.Watch.ResourceHeavyProcesses != 1 { t.Fatalf("expected one heavy process, got %d", got.Watch.ResourceHeavyProcesses) }
}

func TestMemoryHeavyProcessDetected(t *testing.T) {
	current := Snapshot{Checks: []CheckResult{{Key: "process_pressure", Status: StatusNormal, Raw: `{"Name":"memory-hog","ProcessId":55,"CPUPercent":3.0,"MemoryPercent":45.0}`}}}
	got := Analyze(current, nil)
	if got.Watch.ResourceHeavyProcesses != 1 { t.Fatalf("expected one memory-heavy process, got %d", got.Watch.ResourceHeavyProcesses) }
}
