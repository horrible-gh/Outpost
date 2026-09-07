package patrol

import "strings"

func classifyFindings(changes []string, watch WatchSummary) ([]Finding, int) {
	findings := make([]Finding, 0, len(changes))
	for _, message := range changes {
		lower := strings.ToLower(message)
		if strings.Contains(lower, "baseline established") || strings.Contains(lower, "no meaningful security") {
			continue
		}
		category := "health"
		severity := StatusWarning
		switch {
		case strings.Contains(lower, "defender") && strings.Contains(lower, "disabled"):
			category, severity = "protection", StatusDanger
		case strings.Contains(lower, "firewall"):
			category = "protection"
		case strings.Contains(lower, "threat detection"):
			category = "threat"
		case strings.Contains(lower, "failed login"):
			category = "auth"
		case strings.Contains(lower, "local account"):
			category = "identity"
		case strings.Contains(lower, "auto-start service"):
			category = "persistence"
		case strings.Contains(lower, "process"):
			category = "process"
		case strings.Contains(lower, "listener"):
			category = "exposure"
		case strings.Contains(lower, "public connection"):
			category = "network"
		case strings.Contains(lower, "disk"):
			category = "health"
		}
		findings = append(findings, Finding{Category: category, Severity: severity, Message: message})
	}

	score := 0
	score += minInt(watch.FailedLogins*2, 20)
	score += minInt(watch.NewListeners*10, 30)
	score += minInt(watch.NewUsers*15, 30)
	score += minInt(watch.NewServices*15, 30)
	score += minInt(watch.SuspiciousProcesses*20, 40)
	score += minInt(watch.UnusualConnections*10, 30)
	score += minInt(watch.ThreatDetections*30, 60)
	score += minInt(watch.ProtectionIssues*25, 60)
	if score > 100 { score = 100 }
	return findings, score
}

func minInt(a, b int) int { if a < b { return a }; return b }
