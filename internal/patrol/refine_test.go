package patrol

import (
	"strings"
	"testing"
)

func TestWindowsSystemHealthScriptUsesTwoRawSamples(t *testing.T) {
	script := windowsSystemHealthScript()
	for _, want := range []string{
		"Win32_PerfRawData_PerfOS_Processor",
		"Start-Sleep -Milliseconds 1000",
		"Timestamp_Sys100NS",
		"100*(1-(($n2-$n1)/($d2-$d1)))",
		"Win32_PerfFormattedData_PerfOS_Processor",
		"Win32_Processor",
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("expected Windows CPU script to contain %q", want)
		}
	}
	if strings.Count(script, "Win32_PerfRawData_PerfOS_Processor") != 2 {
		t.Fatalf("expected exactly two raw CPU samples, got script: %s", script)
	}
}

func TestValidSystemHealthRaw(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want bool
	}{
		{"normal", `{"CPUPercent":12.5,"MemoryPercent":50.1,"SwapPercent":2.0}`, true},
		{"zero cpu is valid", `{"CPUPercent":0,"MemoryPercent":50,"SwapPercent":0}`, true},
		{"cpu over range", `{"CPUPercent":120,"MemoryPercent":50,"SwapPercent":0}`, false},
		{"negative", `{"CPUPercent":-1,"MemoryPercent":50,"SwapPercent":0}`, false},
		{"invalid json", `not-json`, false},
		{"empty", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := validSystemHealthRaw(tt.raw); got != tt.want {
				t.Fatalf("validSystemHealthRaw(%q)=%v, want %v", tt.raw, got, tt.want)
			}
		})
	}
}
