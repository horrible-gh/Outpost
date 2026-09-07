package patrol

import (
	"encoding/json"
	"fmt"
	"strings"
)

type signatureEntry struct {
	Path   string `json:"Path"`
	Status string `json:"Status"`
	Signer string `json:"Signer"`
}

func enrichChanges(current Snapshot, changes []string) []string {
	check, ok := checkByKey(current, "processes")
	if !ok || check.Status != StatusNormal {
		return changes
	}
	paths := suspiciousProcessPaths(check.Raw)
	if len(paths) == 0 {
		return changes
	}

	replacement := "Suspicious process path(s): " + strings.Join(paths, "; ")
	if signatureCheck, ok := checkByKey(current, "process_signatures"); ok && signatureCheck.Status == StatusNormal {
		if detail := signatureSummary(signatureCheck.Raw); detail != "" {
			replacement += ". Signature check: " + detail
		}
	}
	replacement += "."

	out := make([]string, 0, len(changes))
	replaced := false
	for _, change := range changes {
		lower := strings.ToLower(change)
		if strings.Contains(lower, "process(es) are running from suspicious temporary/download locations") {
			if !replaced {
				out = append(out, replacement)
				replaced = true
			}
			continue
		}
		out = append(out, change)
	}
	if !replaced {
		out = append(out, replacement)
	}
	return out
}

func signatureSummary(raw string) string {
	var many []signatureEntry
	if json.Unmarshal([]byte(raw), &many) != nil {
		var one signatureEntry
		if json.Unmarshal([]byte(raw), &one) != nil || one.Path == "" { return "" }
		many = []signatureEntry{one}
	}
	parts := make([]string, 0, len(many))
	for _, item := range many {
		name := item.Path
		if idx := strings.LastIndexAny(name, `\\/`); idx >= 0 && idx+1 < len(name) { name = name[idx+1:] }
		status := item.Status
		if status == "" { status = "Unknown" }
		if item.Signer != "" {
			parts = append(parts, fmt.Sprintf("%s=%s (%s)", name, status, item.Signer))
		} else {
			parts = append(parts, fmt.Sprintf("%s=%s", name, status))
		}
	}
	return strings.Join(parts, "; ")
}

func buildAssessmentSummary(a Assessment) string {
	switch a.Status {
	case StatusUnknown:
		return "The patrol could not collect enough evidence to make a reliable assessment."
	case StatusDanger:
		if len(a.Findings) > 0 {
			return "Immediate review recommended: " + a.Findings[0].Message
		}
		return "High-risk evidence or critical resource pressure was detected. Review the findings before taking any action."
	case StatusWarning:
		if len(a.Findings) == 1 {
			return "Review recommended: " + a.Findings[0].Message + " No compromise is confirmed."
		}
		if len(a.Findings) > 1 {
			return "Review recommended: multiple meaningful findings were detected. No compromise is confirmed."
		}
		return "The patrol found resource pressure or an unavailable check that should be reviewed."
	default:
		return "No confirmed compromise or meaningful host-health anomaly was detected by the current patrol checks."
	}
}
