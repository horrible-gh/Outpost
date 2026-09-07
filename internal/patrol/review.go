package patrol

import (
	"encoding/json"
	"strings"
)

type ReviewEvidence struct {
	Key     string `json:"key"`
	Status  Status `json:"status"`
	Summary string `json:"summary"`
	Excerpt string `json:"excerpt,omitempty"`
}

type ReviewPacket struct {
	Target    string           `json:"target"`
	OS        string           `json:"os"`
	Sequence  int64            `json:"sequence"`
	Status    Status           `json:"status"`
	RiskScore int              `json:"security_risk_score"`
	Health    HealthSummary    `json:"health"`
	Watch     WatchSummary     `json:"watch"`
	Findings  []Finding        `json:"findings"`
	Next      []string         `json:"next"`
	Evidence  []ReviewEvidence `json:"evidence,omitempty"`
}

func BuildReviewPacket(report PatrolReport) ReviewPacket {
	packet := ReviewPacket{
		Target: report.Snapshot.Target, OS: report.Snapshot.OS, Sequence: report.Snapshot.Sequence,
		Status: report.Assessment.Status, RiskScore: report.Assessment.RiskScore,
		Health: report.Assessment.Health, Watch: report.Assessment.Watch,
		Findings: report.Assessment.Findings, Next: report.Assessment.Next,
	}
	interesting := interestingEvidenceKeys(report.Assessment)
	for _, check := range report.Snapshot.Checks {
		_, selected := interesting[check.Key]
		if check.Status == StatusUnknown || check.Status == StatusWarning || check.Status == StatusDanger { selected = true }
		if !selected { continue }
		packet.Evidence = append(packet.Evidence, ReviewEvidence{Key: check.Key, Status: check.Status, Summary: check.Summary, Excerpt: truncateEvidence(check.Raw, 1600)})
	}
	return packet
}

func interestingEvidenceKeys(a Assessment) map[string]struct{} {
	keys := map[string]struct{}{}
	if a.Watch.NewListeners > 0 || a.Watch.UnusualConnections > 0 { keys["network"] = struct{}{} }
	if a.Watch.FailedLogins > 0 { keys["failed_logins"] = struct{}{} }
	if a.Watch.NewUsers > 0 { keys["users"] = struct{}{} }
	if a.Watch.NewServices > 0 { keys["services"] = struct{}{} }
	if a.Watch.SuspiciousProcesses > 0 { keys["processes"] = struct{}{} }
	if a.Watch.ResourceHeavyProcesses > 0 { keys["process_pressure"] = struct{}{} }
	if a.Watch.ThreatDetections > 0 { keys["defender_threats"] = struct{}{} }
	if a.Watch.ProtectionIssues > 0 { keys["defender_status"] = struct{}{}; keys["firewall"] = struct{}{} }
	if a.Health.CPUPercent >= 85 || a.Health.MemoryPercent >= 85 || a.Health.SwapPercent >= 70 { keys["system_health"] = struct{}{} }
	return keys
}

func truncateEvidence(raw string, limit int) string {
	raw = strings.TrimSpace(raw)
	if limit <= 0 || len(raw) <= limit { return raw }
	return raw[:limit] + "…"
}

func (p ReviewPacket) JSON() ([]byte, error) { return json.Marshal(p) }
