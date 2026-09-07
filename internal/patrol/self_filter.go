package patrol

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"strconv"
	"strings"
)

// excludeSelfProcess removes Outpost's own process from the generic process
// evidence before anomaly heuristics run. The monitor itself is expected to be
// present and should not be treated as a suspicious workload.
func excludeSelfProcess(snapshot *Snapshot) {
	if snapshot == nil {
		return
	}
	pid := os.Getpid()
	for i := range snapshot.Checks {
		if snapshot.Checks[i].Key != "processes" || snapshot.Checks[i].Status != StatusNormal {
			continue
		}
		raw, changed := removeProcessPID(snapshot.Checks[i].Raw, pid, snapshot.OS)
		if !changed {
			return
		}
		snapshot.Checks[i].Raw = raw
		hash := sha256.Sum256([]byte(raw))
		snapshot.Checks[i].Fingerprint = hex.EncodeToString(hash[:])
		return
	}
}

func removeProcessPID(raw string, pid int, goos string) (string, bool) {
	if strings.EqualFold(goos, "windows") {
		var many []map[string]any
		if json.Unmarshal([]byte(raw), &many) == nil {
			filtered := many[:0]
			changed := false
			for _, item := range many {
				if jsonPID(item["ProcessId"]) == pid {
					changed = true
					continue
				}
				filtered = append(filtered, item)
			}
			if !changed {
				return raw, false
			}
			b, err := json.Marshal(filtered)
			if err != nil {
				return raw, false
			}
			return string(b), true
		}

		var one map[string]any
		if json.Unmarshal([]byte(raw), &one) == nil && jsonPID(one["ProcessId"]) == pid {
			return "[]", true
		}
		return raw, false
	}

	// Linux ps output begins each row with PID. Preserve headers and formatting
	// while excluding only the exact Outpost PID.
	pidText := strconv.Itoa(pid)
	lines := strings.Split(raw, "\n")
	out := make([]string, 0, len(lines))
	changed := false
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) > 0 && fields[0] == pidText {
			changed = true
			continue
		}
		out = append(out, line)
	}
	if !changed {
		return raw, false
	}
	return strings.Join(out, "\n"), true
}

func jsonPID(v any) int {
	switch value := v.(type) {
	case float64:
		return int(value)
	case int:
		return value
	case json.Number:
		i, _ := value.Int64()
		return int(i)
	case string:
		i, _ := strconv.Atoi(value)
		return i
	default:
		return 0
	}
}
