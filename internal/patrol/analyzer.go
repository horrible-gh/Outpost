package patrol

import "fmt"

func Analyze(current Snapshot, previous *Snapshot) Assessment {
	assessment := Assessment{Status: StatusNormal, Summary: "No confirmed compromise detected by the current patrol checks."}

	unknownCount := 0
	for _, check := range current.Checks {
		switch check.Status {
		case StatusDanger:
			assessment.Status = StatusDanger
		case StatusWarning:
			if assessment.Status != StatusDanger { assessment.Status = StatusWarning }
		case StatusUnknown:
			unknownCount++
		}
	}
	if len(current.Checks) > 0 && unknownCount == len(current.Checks) { assessment.Status = StatusUnknown }

	semanticStatus, changes, next, watch := inspectMeaningfulChanges(current, previous)
	assessment.Watch = watch
	if semanticStatus == StatusDanger || (semanticStatus == StatusWarning && assessment.Status == StatusNormal) { assessment.Status = semanticStatus }

	if previous == nil {
		changes = append(changes, "Baseline established from the first patrol.")
		next = append(next, "Compare the next patrol with this baseline.")
	}
	if unknownCount > 0 { next = append(next, fmt.Sprintf("Retry %d unavailable check(s) on the next patrol.", unknownCount)) }
	if len(changes) == 0 { changes = []string{"No meaningful security or health change detected since the previous patrol."} }
	if len(next) == 0 { next = []string{"Continue scheduled patrols."} }

	assessment.Changes = uniqueSorted(changes)
	assessment.Next = uniqueSorted(next)
	switch assessment.Status {
	case StatusDanger:
		assessment.Summary = "High-risk evidence was detected. Review the findings before taking any action."
	case StatusWarning:
		assessment.Summary = "The patrol found exposure or a meaningful change that should be reviewed. No compromise is confirmed."
	case StatusUnknown:
		assessment.Summary = "The patrol could not collect enough evidence to make a reliable assessment."
	}
	return assessment
}
