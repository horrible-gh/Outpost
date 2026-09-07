package patrol

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

type diskEntry struct {
	DeviceID  string  `json:"DeviceID"`
	Size      float64 `json:"Size"`
	FreeSpace float64 `json:"FreeSpace"`
}

type networkEntry struct {
	State        int    `json:"State"`
	LocalAddress string `json:"LocalAddress"`
	LocalPort    int    `json:"LocalPort"`
}

func inspectMeaningfulChanges(current Snapshot, previous *Snapshot) (Status, []string, []string) {
	status := StatusNormal
	var changes []string
	var next []string

	if check, ok := checkByKey(current, "disk"); ok && check.Status == StatusNormal {
		for _, d := range decodeDisks(check.Raw) {
			if d.Size <= 0 {
				continue
			}
			used := (1 - d.FreeSpace/d.Size) * 100
			if used >= 95 {
				status = StatusDanger
				changes = append(changes, fmt.Sprintf("Disk %s is %.1f%% used.", d.DeviceID, used))
			} else if used >= 85 && status != StatusDanger {
				status = StatusWarning
				changes = append(changes, fmt.Sprintf("Disk %s is %.1f%% used.", d.DeviceID, used))
			}
		}
	}

	if check, ok := checkByKey(current, "failed_logins"); ok && check.Status == StatusNormal {
		count := jsonItemCount(check.Raw)
		if count > 0 {
			if status == StatusNormal {
				status = StatusWarning
			}
			changes = append(changes, fmt.Sprintf("%d failed login event(s) are present in the patrol window.", count))
			next = append(next, "Review failed login source addresses and account names.")
		}
	}

	if check, ok := checkByKey(current, "network"); ok && check.Status == StatusNormal {
		currentListeners := listeners(check.Raw)
		if previous == nil {
			var sensitive []string
			for listener := range currentListeners {
				if sensitiveListener(listener) {
					sensitive = append(sensitive, listener)
				}
			}
			if len(sensitive) > 0 {
				if status == StatusNormal {
					status = StatusWarning
				}
				sort.Strings(sensitive)
				changes = append(changes, "Baseline exposes sensitive listener(s): "+strings.Join(sensitive, ", ")+".")
				next = append(next, "Confirm that sensitive listeners are intentional and firewall-restricted.")
			}
		} else if old, ok := checkByKey(*previous, "network"); ok && old.Status == StatusNormal {
			oldListeners := listeners(old.Raw)
			var added []string
			for listener := range currentListeners {
				if _, exists := oldListeners[listener]; !exists {
					added = append(added, listener)
				}
			}
			if len(added) > 0 {
				if status == StatusNormal {
					status = StatusWarning
				}
				sort.Strings(added)
				changes = append(changes, "New externally reachable listener(s): "+strings.Join(added, ", ")+".")
				next = append(next, "Verify the owning process and purpose of each new listener.")
			}
		}
	}

	return status, uniqueSorted(changes), uniqueSorted(next)
}

func checkByKey(snapshot Snapshot, key string) (CheckResult, bool) {
	for _, check := range snapshot.Checks {
		if check.Key == key {
			return check, true
		}
	}
	return CheckResult{}, false
}

func decodeDisks(raw string) []diskEntry {
	var many []diskEntry
	if json.Unmarshal([]byte(raw), &many) == nil {
		return many
	}
	var one diskEntry
	if json.Unmarshal([]byte(raw), &one) == nil {
		return []diskEntry{one}
	}
	return nil
}

func listeners(raw string) map[string]struct{} {
	var many []networkEntry
	if json.Unmarshal([]byte(raw), &many) != nil {
		var one networkEntry
		if json.Unmarshal([]byte(raw), &one) != nil {
			return map[string]struct{}{}
		}
		many = []networkEntry{one}
	}
	out := make(map[string]struct{})
	for _, n := range many {
		if n.State != 2 || n.LocalPort <= 0 || n.LocalAddress == "127.0.0.1" || n.LocalAddress == "::1" {
			continue
		}
		addr := n.LocalAddress
		if addr == "0.0.0.0" || addr == "::" || addr == "" {
			addr = "*"
		}
		out[fmt.Sprintf("%s:%d", addr, n.LocalPort)] = struct{}{}
	}
	return out
}

func jsonItemCount(raw string) int {
	raw = strings.TrimSpace(raw)
	if raw == "" || raw == "[]" || raw == "null" {
		return 0
	}
	var many []json.RawMessage
	if json.Unmarshal([]byte(raw), &many) == nil {
		return len(many)
	}
	var one json.RawMessage
	if json.Unmarshal([]byte(raw), &one) == nil {
		return 1
	}
	return 0
}

func sensitiveListener(value string) bool {
	for _, port := range []string{":22", ":135", ":139", ":445", ":3389", ":5985", ":5986"} {
		if strings.HasSuffix(value, port) {
			return true
		}
	}
	return false
}

func uniqueSorted(values []string) []string {
	set := make(map[string]struct{}, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" {
			set[value] = struct{}{}
		}
	}
	out := make([]string, 0, len(set))
	for value := range set {
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}
