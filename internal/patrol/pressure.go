package patrol

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

type processPressureEntry struct {
	Name          string  `json:"Name"`
	ProcessID     int     `json:"ProcessId"`
	CPUPercent    float64 `json:"CPUPercent"`
	MemoryPercent float64 `json:"MemoryPercent"`
}

func inspectProcessPressure(current Snapshot) (int, Status, []string, []string) {
	check, ok := checkByKey(current, "process_pressure")
	if !ok || check.Status != StatusNormal { return 0, StatusNormal, nil, nil }
	entries := decodeProcessPressure(check.Raw)
	count := 0
	status := StatusNormal
	var changes []string
	var next []string
	for _, p := range entries {
		if p.CPUPercent >= 90 || p.MemoryPercent >= 40 {
			count++
			status = atLeastWarning(status)
			changes = append(changes, fmt.Sprintf("Resource-heavy process %s (PID %d): CPU %.1f%%, memory %.1f%%.", p.Name, p.ProcessID, p.CPUPercent, p.MemoryPercent))
		}
	}
	if count > 0 { next = append(next, "Re-check resource-heavy processes and confirm whether the load is expected.") }
	return count, status, uniqueSorted(changes), next
}

func decodeProcessPressure(raw string) []processPressureEntry {
	var many []processPressureEntry
	if json.Unmarshal([]byte(raw), &many) == nil { return many }
	var one processPressureEntry
	if json.Unmarshal([]byte(raw), &one) == nil && one.Name != "" { return []processPressureEntry{one} }
	var out []processPressureEntry
	for _, line := range strings.Split(raw, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 4 { continue }
		pid, err1 := strconv.Atoi(fields[0])
		cpu, err2 := strconv.ParseFloat(fields[len(fields)-2], 64)
		mem, err3 := strconv.ParseFloat(fields[len(fields)-1], 64)
		if err1 != nil || err2 != nil || err3 != nil { continue }
		name := strings.Join(fields[1:len(fields)-2], " ")
		out = append(out, processPressureEntry{Name: name, ProcessID: pid, CPUPercent: cpu, MemoryPercent: mem})
	}
	return out
}
