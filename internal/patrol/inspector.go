package patrol

import (
	"encoding/json"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
)

type diskEntry struct {
	DeviceID    string  `json:"DeviceID"`
	Size        float64 `json:"Size"`
	FreeSpace   float64 `json:"FreeSpace"`
	UsedPercent float64 `json:"-"`
}

type networkEntry struct {
	State         int    `json:"State"`
	LocalAddress  string `json:"LocalAddress"`
	LocalPort     int    `json:"LocalPort"`
	RemoteAddress string `json:"RemoteAddress"`
	RemotePort    int    `json:"RemotePort"`
	OwningProcess int    `json:"OwningProcess"`
}

type processEntry struct {
	Name           string `json:"Name"`
	ProcessID      int    `json:"ProcessId"`
	ExecutablePath string `json:"ExecutablePath"`
	CommandLine    string `json:"CommandLine"`
}

type defenderStatusEntry struct {
	AntivirusEnabled          bool `json:"AntivirusEnabled"`
	AntispywareEnabled        bool `json:"AntispywareEnabled"`
	RealTimeProtectionEnabled bool `json:"RealTimeProtectionEnabled"`
	BehaviorMonitorEnabled    bool `json:"BehaviorMonitorEnabled"`
}

type firewallProfileEntry struct {
	Name    string `json:"Name"`
	Enabled bool   `json:"Enabled"`
}

func inspectMeaningfulChanges(current Snapshot, previous *Snapshot) (Status, []string, []string, WatchSummary) {
	status := StatusNormal
	var changes []string
	var next []string
	watch := WatchSummary{}

	if check, ok := checkByKey(current, "disk"); ok && check.Status == StatusNormal {
		for _, d := range decodeDisks(check.Raw) {
			used := d.UsedPercent
			if used <= 0 && d.Size > 0 { used = (1 - d.FreeSpace/d.Size) * 100 }
			if used <= 0 { continue }
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
		watch.FailedLogins = eventCount(check.Raw)
		if watch.FailedLogins > 0 {
			status = atLeastWarning(status)
			changes = append(changes, fmt.Sprintf("%d failed login event(s) are present in the patrol window.", watch.FailedLogins))
			next = append(next, "Review failed login source addresses and account names.")
		}
	}

	if check, ok := checkByKey(current, "network"); ok && check.Status == StatusNormal {
		curListeners := listeners(check.Raw)
		watch.UnusualConnections = len(unusualPublicConnections(check.Raw))
		if watch.UnusualConnections > 0 {
			status = atLeastWarning(status)
			changes = append(changes, fmt.Sprintf("%d public connection(s) use ports other than common web ports.", watch.UnusualConnections))
			next = append(next, "Review unusual public destinations and their owning processes.")
		}
		if previous == nil {
			var sensitive []string
			for l := range curListeners { if sensitiveListener(l) { sensitive = append(sensitive, l) } }
			if len(sensitive) > 0 {
				status = atLeastWarning(status)
				sort.Strings(sensitive)
				changes = append(changes, "Baseline exposes sensitive listener(s): "+strings.Join(sensitive, ", ")+".")
				next = append(next, "Confirm that sensitive listeners are intentional and firewall-restricted.")
			}
		} else if old, ok := checkByKey(*previous, "network"); ok && old.Status == StatusNormal {
			oldListeners := listeners(old.Raw)
			var added []string
			for l := range curListeners { if _, exists := oldListeners[l]; !exists { added = append(added, l) } }
			watch.NewListeners = len(added)
			if len(added) > 0 {
				status = atLeastWarning(status)
				sort.Strings(added)
				changes = append(changes, "New externally reachable listener(s): "+strings.Join(added, ", ")+".")
				next = append(next, "Verify the owning process and purpose of each new listener.")
			}
		}
	}

	if check, ok := checkByKey(current, "processes"); ok && check.Status == StatusNormal {
		paths := suspiciousProcessPaths(check.Raw)
		watch.SuspiciousProcesses = len(paths)
		if len(paths) > 0 {
			status = atLeastWarning(status)
			changes = append(changes, fmt.Sprintf("%d process(es) are running from suspicious temporary/download locations.", len(paths)))
			next = append(next, "Review suspicious process paths and signatures before taking action.")
		}
	}

	if check, ok := checkByKey(current, "defender_threats"); ok && check.Status == StatusNormal {
		watch.ThreatDetections = jsonItemCount(check.Raw)
		if watch.ThreatDetections > 0 {
			status = atLeastWarning(status)
			changes = append(changes, fmt.Sprintf("Windows Defender recorded %d threat detection(s) in the last 24 hours.", watch.ThreatDetections))
			next = append(next, "Review Defender threat resources, action status, and detection timestamps.")
		}
	}

	if check, ok := checkByKey(current, "defender_status"); ok && check.Status == StatusNormal {
		issues := defenderProtectionIssues(check.Raw)
		watch.ProtectionIssues += len(issues)
		if len(issues) > 0 {
			status = StatusDanger
			changes = append(changes, issues...)
			next = append(next, "Confirm why Windows Defender protection components are disabled.")
		}
	}

	if check, ok := checkByKey(current, "firewall"); ok && check.Status == StatusNormal {
		issues := disabledFirewallProfiles(check.Raw)
		watch.ProtectionIssues += len(issues)
		if len(issues) > 0 {
			status = atLeastWarning(status)
			changes = append(changes, issues...)
			next = append(next, "Confirm whether disabled firewall profiles are intentional.")
		}
	}

	if previous != nil {
		if cur, ok := checkByKey(current, "users"); ok && cur.Status == StatusNormal {
			if old, ok := checkByKey(*previous, "users"); ok && old.Status == StatusNormal {
				added := addedNamedObjects(cur.Raw, old.Raw, "Name")
				watch.NewUsers = len(added)
				if len(added) > 0 {
					status = atLeastWarning(status)
					changes = append(changes, "New local account(s): "+strings.Join(added, ", ")+".")
					next = append(next, "Confirm that each new local account is expected.")
				}
			}
		}
		if cur, ok := checkByKey(current, "services"); ok && cur.Status == StatusNormal {
			if old, ok := checkByKey(*previous, "services"); ok && old.Status == StatusNormal {
				added := addedNamedObjects(cur.Raw, old.Raw, "Name")
				watch.NewServices = len(added)
				if len(added) > 0 {
					status = atLeastWarning(status)
					changes = append(changes, "New auto-start service(s): "+strings.Join(added, ", ")+".")
					next = append(next, "Verify new auto-start services and their executable paths.")
				}
			}
		}
	}

	return status, uniqueSorted(changes), uniqueSorted(next), watch
}

func atLeastWarning(s Status) Status { if s == StatusDanger { return s }; return StatusWarning }

func checkByKey(snapshot Snapshot, key string) (CheckResult, bool) {
	for _, check := range snapshot.Checks { if check.Key == key { return check, true } }
	return CheckResult{}, false
}

func decodeDisks(raw string) []diskEntry {
	var many []diskEntry
	if json.Unmarshal([]byte(raw), &many) == nil { return many }
	var one diskEntry
	if json.Unmarshal([]byte(raw), &one) == nil { return []diskEntry{one} }
	var out []diskEntry
	for i, line := range strings.Split(raw, "\n") {
		if i == 0 || strings.TrimSpace(line) == "" { continue }
		fields := strings.Fields(line)
		if len(fields) < 6 { continue }
		pct, err := strconv.ParseFloat(strings.TrimSuffix(fields[4], "%"), 64)
		if err != nil { continue }
		out = append(out, diskEntry{DeviceID: fields[0] + " (" + fields[5] + ")", UsedPercent: pct})
	}
	return out
}

func decodeNetwork(raw string) []networkEntry {
	var many []networkEntry
	if json.Unmarshal([]byte(raw), &many) == nil { return many }
	var one networkEntry
	if json.Unmarshal([]byte(raw), &one) == nil { return []networkEntry{one} }
	return decodeSS(raw)
}

func decodeSS(raw string) []networkEntry {
	var out []networkEntry
	for _, line := range strings.Split(raw, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 5 || strings.EqualFold(fields[0], "Netid") { continue }
		stateIndex := 1
		if strings.EqualFold(fields[0], "LISTEN") || strings.EqualFold(fields[0], "ESTAB") { stateIndex = 0 }
		if len(fields) <= stateIndex+4 { continue }
		stateText := strings.ToUpper(fields[stateIndex])
		state := 0
		switch stateText { case "LISTEN": state = 2; case "ESTAB", "ESTABLISHED": state = 5; default: continue }
		localIndex := stateIndex + 3
		remoteIndex := stateIndex + 4
		localAddr, localPort := splitEndpoint(fields[localIndex])
		remoteAddr, remotePort := splitEndpoint(fields[remoteIndex])
		out = append(out, networkEntry{State: state, LocalAddress: localAddr, LocalPort: localPort, RemoteAddress: remoteAddr, RemotePort: remotePort})
	}
	return out
}

func splitEndpoint(value string) (string, int) {
	value = strings.TrimSpace(value)
	if value == "" { return "", 0 }
	if host, port, err := net.SplitHostPort(value); err == nil {
		p, _ := strconv.Atoi(port); return strings.Trim(host, "[]"), p
	}
	idx := strings.LastIndex(value, ":")
	if idx < 0 { return strings.Trim(value, "[]"), 0 }
	host := strings.Trim(value[:idx], "[]")
	portText := value[idx+1:]
	if portText == "*" { return host, 0 }
	p, _ := strconv.Atoi(portText)
	return host, p
}

func listeners(raw string) map[string]struct{} {
	out := make(map[string]struct{})
	for _, n := range decodeNetwork(raw) {
		if n.State != 2 || n.LocalPort <= 0 || n.LocalAddress == "127.0.0.1" || n.LocalAddress == "::1" { continue }
		addr := n.LocalAddress
		if addr == "0.0.0.0" || addr == "::" || addr == "*" || addr == "" { addr = "*" }
		out[fmt.Sprintf("%s:%d", addr, n.LocalPort)] = struct{}{}
	}
	return out
}

func unusualPublicConnections(raw string) []string {
	set := map[string]struct{}{}
	for _, n := range decodeNetwork(raw) {
		if n.State != 5 || n.RemotePort <= 0 || n.RemoteAddress == "" || n.RemotePort == 80 || n.RemotePort == 443 { continue }
		ip := net.ParseIP(strings.Trim(n.RemoteAddress, "[]"))
		if ip == nil || ip.IsLoopback() || ip.IsPrivate() || ip.IsUnspecified() { continue }
		set[fmt.Sprintf("%s:%d", n.RemoteAddress, n.RemotePort)] = struct{}{}
	}
	out := make([]string, 0, len(set)); for v := range set { out = append(out, v) }; sort.Strings(out); return out
}

func suspiciousProcessPaths(raw string) []string {
	var many []processEntry
	if json.Unmarshal([]byte(raw), &many) == nil {
		var out []string
		for _, p := range many {
			path := strings.ToLower(strings.ReplaceAll(p.ExecutablePath, "/", "\\"))
			if path == "" { continue }
			if strings.Contains(path, "\\temp\\") || strings.Contains(path, "\\downloads\\") || strings.HasPrefix(path, "c:\\windows\\temp\\") {
				out = append(out, fmt.Sprintf("%s (%s)", p.Name, p.ExecutablePath))
			}
		}
		return uniqueSorted(out)
	}
	var one processEntry
	if json.Unmarshal([]byte(raw), &one) == nil && one.Name != "" {
		path := strings.ToLower(strings.ReplaceAll(one.ExecutablePath, "/", "\\"))
		if strings.Contains(path, "\\temp\\") || strings.Contains(path, "\\downloads\\") { return []string{fmt.Sprintf("%s (%s)", one.Name, one.ExecutablePath)} }
		return nil
	}
	var out []string
	for i, line := range strings.Split(raw, "\n") {
		if i == 0 { continue }
		lower := strings.ToLower(line)
		if strings.Contains(lower, "/tmp/") || strings.Contains(lower, "/var/tmp/") || strings.Contains(lower, "/dev/shm/") {
			out = append(out, strings.TrimSpace(line))
		}
	}
	return uniqueSorted(out)
}

func defenderProtectionIssues(raw string) []string {
	var d defenderStatusEntry
	if json.Unmarshal([]byte(raw), &d) != nil { return nil }
	var issues []string
	if !d.AntivirusEnabled { issues = append(issues, "Windows Defender antivirus is disabled.") }
	if !d.AntispywareEnabled { issues = append(issues, "Windows Defender antispyware protection is disabled.") }
	if !d.RealTimeProtectionEnabled { issues = append(issues, "Windows Defender real-time protection is disabled.") }
	if !d.BehaviorMonitorEnabled { issues = append(issues, "Windows Defender behavior monitoring is disabled.") }
	return issues
}

func disabledFirewallProfiles(raw string) []string {
	var profiles []firewallProfileEntry
	if json.Unmarshal([]byte(raw), &profiles) != nil {
		var one firewallProfileEntry
		if json.Unmarshal([]byte(raw), &one) != nil { return nil }
		profiles = []firewallProfileEntry{one}
	}
	var issues []string
	for _, p := range profiles { if !p.Enabled { issues = append(issues, fmt.Sprintf("Windows Firewall profile %s is disabled.", p.Name)) } }
	return issues
}

func addedNamedObjects(currentRaw, previousRaw, field string) []string {
	decode := func(raw string) map[string]struct{} {
		set := map[string]struct{}{}
		var many []map[string]any
		if json.Unmarshal([]byte(raw), &many) == nil {
			for _, item := range many { if v, ok := item[field].(string); ok && v != "" { set[v] = struct{}{} } }
			return set
		}
		var one map[string]any
		if json.Unmarshal([]byte(raw), &one) == nil {
			if v, ok := one[field].(string); ok && v != "" { set[v] = struct{}{} }
			return set
		}
		for _, line := range strings.Split(raw, "\n") {
			line = strings.TrimSpace(line); if line == "" { continue }
			name := ""
			if idx := strings.Index(line, ":"); idx > 0 { name = line[:idx] } else if fields := strings.Fields(line); len(fields) > 0 { name = fields[0] }
			if name != "" { set[name] = struct{}{} }
		}
		return set
	}
	cur, old := decode(currentRaw), decode(previousRaw)
	var added []string
	for name := range cur { if _, exists := old[name]; !exists { added = append(added, name) } }
	sort.Strings(added); return added
}

func eventCount(raw string) int {
	if n := jsonItemCount(raw); n > 0 || strings.TrimSpace(raw) == "[]" { return n }
	count := 0
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.Contains(strings.ToLower(line), "begins") { continue }
		count++
	}
	return count
}

func jsonItemCount(raw string) int {
	raw = strings.TrimSpace(raw); if raw == "" || raw == "[]" || raw == "null" { return 0 }
	var many []json.RawMessage; if json.Unmarshal([]byte(raw), &many) == nil { return len(many) }
	var one json.RawMessage; if json.Unmarshal([]byte(raw), &one) == nil { return 1 }; return 0
}

func sensitiveListener(value string) bool {
	for _, port := range []string{":22", ":135", ":139", ":445", ":3389", ":5985", ":5986"} { if strings.HasSuffix(value, port) { return true } }
	return false
}

func uniqueSorted(values []string) []string {
	set := make(map[string]struct{}, len(values)); for _, value := range values { value = strings.TrimSpace(value); if value != "" { set[value] = struct{}{} } }
	out := make([]string, 0, len(set)); for value := range set { out = append(out, value) }; sort.Strings(out); return out
}
