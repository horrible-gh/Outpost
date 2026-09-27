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


func TestSystemHealthUsesProcessPressureFallbackOnWindowsZeroCPU(t *testing.T) {
	current := Snapshot{
		OS: "windows",
		Checks: []CheckResult{
			{Key: "system_health", Status: StatusNormal, Raw: `{"CPUPercent":0.0,"CPUSource":"raw-perf-1s","MemoryPercent":55.0,"SwapPercent":10.0}`},
			{Key: "process_pressure", Status: StatusNormal, Raw: `[
				{"Name":"worker","ProcessId":10,"CPUPercent":4.2,"MemoryPercent":2.0},
				{"Name":"browser","ProcessId":11,"CPUPercent":1.8,"MemoryPercent":3.0}
			]`},
		},
	}
	got := Analyze(current, nil)
	if got.Health.CPUPercent != 6.0 {
		t.Fatalf("expected process CPU fallback 6.0, got %#v", got.Health)
	}
	if got.Health.CPUSource != "process-pressure-fallback" {
		t.Fatalf("expected process fallback source, got %q", got.Health.CPUSource)
	}
}

func TestSystemHealthKeepsNonZeroSystemCPU(t *testing.T) {
	current := Snapshot{
		OS: "windows",
		Checks: []CheckResult{
			{Key: "system_health", Status: StatusNormal, Raw: `{"CPUPercent":3.5,"CPUSource":"raw-perf-1s","MemoryPercent":55.0,"SwapPercent":10.0}`},
			{Key: "process_pressure", Status: StatusNormal, Raw: `[
				{"Name":"worker","ProcessId":10,"CPUPercent":8.0,"MemoryPercent":2.0}
			]`},
		},
	}
	got := Analyze(current, nil)
	if got.Health.CPUPercent != 3.5 {
		t.Fatalf("expected system CPU to remain authoritative, got %#v", got.Health)
	}
	if got.Health.CPUSource != "raw-perf-1s" {
		t.Fatalf("expected raw source, got %q", got.Health.CPUSource)
	}
}
