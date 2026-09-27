package patrol

import (
	"encoding/json"
	"fmt"
	"math"
)

type systemHealthEntry struct {
	CPUPercent    float64 `json:"CPUPercent"`
	CPUSource     string  `json:"CPUSource"`
	MemoryPercent float64 `json:"MemoryPercent"`
	SwapPercent   float64 `json:"SwapPercent"`
}

func inspectSystemHealth(current Snapshot) (HealthSummary, Status, []string, []string) {
	check, ok := checkByKey(current, "system_health")
	if !ok || check.Status != StatusNormal { return HealthSummary{}, StatusNormal, nil, nil }
	var entry systemHealthEntry
	if json.Unmarshal([]byte(check.Raw), &entry) != nil { return HealthSummary{}, StatusNormal, nil, nil }

	cpu := cpu
	cpuSource := entry.CPUSource
	if cpuSource == "" {
		cpuSource = "system-health"
	}
	// Some Windows hosts report 0.0 from the total CPU WMI counters while
	// per-process performance counters are clearly non-zero. In that specific
	// case use the observed process-pressure sum as a conservative lower bound.
	// We do not override a non-zero system CPU reading because the two collectors
	// can use slightly different sampling windows.
	if current.OS == "windows" && cpu < 0.1 {
		if processCPU := observedProcessCPU(current); processCPU >= 0.1 {
			cpu = processCPU
			cpuSource = "process-pressure-fallback"
		}
	}
	health := HealthSummary{CPUPercent: cpu, CPUSource: cpuSource, MemoryPercent: entry.MemoryPercent, SwapPercent: entry.SwapPercent}
	status := StatusNormal
	var changes []string
	var next []string

	if cpu >= 95 {
		status = StatusDanger
		changes = append(changes, fmt.Sprintf("CPU utilization is %.1f%%.", cpu))
		next = append(next, "Inspect the highest CPU processes if the pressure persists.")
	} else if cpu >= 85 {
		status = StatusWarning
		changes = append(changes, fmt.Sprintf("CPU utilization is %.1f%%.", cpu))
		next = append(next, "Re-check CPU pressure on the next patrol.")
	}

	if entry.MemoryPercent >= 95 {
		status = StatusDanger
		changes = append(changes, fmt.Sprintf("Memory utilization is %.1f%%.", entry.MemoryPercent))
		next = append(next, "Inspect the highest memory processes and memory growth.")
	} else if entry.MemoryPercent >= 85 {
		status = atLeastWarning(status)
		changes = append(changes, fmt.Sprintf("Memory utilization is %.1f%%.", entry.MemoryPercent))
		next = append(next, "Re-check memory pressure on the next patrol.")
	}

	if entry.SwapPercent >= 90 {
		status = StatusDanger
		changes = append(changes, fmt.Sprintf("Swap utilization is %.1f%%.", entry.SwapPercent))
		next = append(next, "Inspect memory pressure and sustained swap usage.")
	} else if entry.SwapPercent >= 70 {
		status = atLeastWarning(status)
		changes = append(changes, fmt.Sprintf("Swap utilization is %.1f%%.", entry.SwapPercent))
		next = append(next, "Watch for sustained swap growth.")
	}
	return health, status, changes, next
}


func observedProcessCPU(current Snapshot) float64 {
	check, ok := checkByKey(current, "process_pressure")
	if !ok || check.Status != StatusNormal {
		return 0
	}
	total := 0.0
	for _, entry := range decodeProcessPressure(check.Raw) {
		if entry.CPUPercent > 0 {
			total += entry.CPUPercent
		}
	}
	if total > 100 {
		total = 100
	}
	return math.Round(total*10) / 10
}
