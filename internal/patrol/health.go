package patrol

import (
	"encoding/json"
	"fmt"
)

type systemHealthEntry struct {
	CPUPercent    float64 `json:"CPUPercent"`
	MemoryPercent float64 `json:"MemoryPercent"`
	SwapPercent   float64 `json:"SwapPercent"`
}

func inspectSystemHealth(current Snapshot) (HealthSummary, Status, []string, []string) {
	check, ok := checkByKey(current, "system_health")
	if !ok || check.Status != StatusNormal { return HealthSummary{}, StatusNormal, nil, nil }
	var entry systemHealthEntry
	if json.Unmarshal([]byte(check.Raw), &entry) != nil { return HealthSummary{}, StatusNormal, nil, nil }

	health := HealthSummary{CPUPercent: entry.CPUPercent, MemoryPercent: entry.MemoryPercent, SwapPercent: entry.SwapPercent}
	status := StatusNormal
	var changes []string
	var next []string

	if entry.CPUPercent >= 95 {
		status = StatusDanger
		changes = append(changes, fmt.Sprintf("CPU utilization is %.1f%%.", entry.CPUPercent))
		next = append(next, "Inspect the highest CPU processes if the pressure persists.")
	} else if entry.CPUPercent >= 85 {
		status = StatusWarning
		changes = append(changes, fmt.Sprintf("CPU utilization is %.1f%%.", entry.CPUPercent))
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
