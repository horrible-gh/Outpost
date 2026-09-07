package patrol

import "strings"

type Analyzer interface {
	Analyze(current Snapshot, previous *Snapshot) ([]Check, []string, []string, Severity)
}

type HeuristicAnalyzer struct{}

func NewHeuristicAnalyzer() *HeuristicAnalyzer { return &HeuristicAnalyzer{} }

func (a *HeuristicAnalyzer) Analyze(current Snapshot, previous *Snapshot) ([]Check, []string, []string, Severity) {
	checks := []Check{}
	status := SeverityNormal

	add := func(key, label, summary, detail string, severity Severity) {
		checks = append(checks, Check{Key: key, Label: label, Summary: summary, Detail: detail, Severity: severity})
		if severityRank(severity) > severityRank(status) { status = severity }
	}

	for _, item := range []struct{ key, label string }{
		{"disk", "Disk"}, {"processes", "Processes"}, {"network", "Network"},
		{"logins", "Login history"}, {"failed_logins", "Failed logins"}, {"security_updates", "Security updates"},
	} {
		v := strings.TrimSpace(current.Evidence[item.key])
		if v == "" || strings.HasPrefix(v, "unavailable:") {
			add(item.key, item.label, "check unavailable", trim(v, 240), SeverityUnknown)
		} else {
			add(item.key, item.label, "collected", "", SeverityNormal)
		}
	}

	assessment := []string{"No confirmed compromise detected by the baseline checks."}
	next := []string{"Compare the next patrol with this baseline."}
	if previous != nil {
		changed := 0
		for k, v := range current.Evidence {
			if previous.Evidence[k] != "" && previous.Evidence[k] != v { changed++ }
		}
		if changed > 0 {
			assessment = append(assessment, "Observed changes in "+itoa(changed)+" evidence categories since the previous patrol.")
			next = append(next, "Re-check changed categories on the next patrol.")
		}
	}
	return checks, assessment, next, status
}

func severityRank(s Severity) int {
	switch s {
	case SeverityDanger: return 3
	case SeverityWarning: return 2
	case SeverityUnknown: return 1
	default: return 0
	}
}

func trim(s string, n int) string {
	if len(s) <= n { return s }
	return s[:n] + "..."
}

func itoa(n int) string {
	if n == 0 { return "0" }
	b := make([]byte, 0, 12)
	for n > 0 { b = append([]byte{byte('0' + n%10)}, b...); n /= 10 }
	return string(b)
}
