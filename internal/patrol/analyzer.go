package patrol

import (
	"fmt"
	"sort"
)

func Analyze(current Snapshot, previous *Snapshot) Assessment {
	assessment := Assessment{
		Status:  StatusNormal,
		Summary: "No confirmed compromise detected by the baseline checks.",
	}

	unknownCount := 0
	warningCount := 0
	dangerCount := 0

	for _, check := range current.Checks {
		switch check.Status {
		case StatusDanger:
			dangerCount++
		case StatusWarning:
			warningCount++
		case StatusUnknown:
			unknownCount++
		}
	}

	switch {
	case dangerCount > 0:
		assessment.Status = StatusDanger
	case warningCount > 0:
		assessment.Status = StatusWarning
	case len(current.Checks) > 0 && unknownCount == len(current.Checks):
		assessment.Status = StatusUnknown
	default:
		assessment.Status = StatusNormal
	}

	if previous == nil {
		assessment.Changes = []string{"Baseline established from the first patrol."}
		assessment.Next = []string{"Compare the next patrol with this baseline."}
		if unknownCount > 0 {
			assessment.Next = append(assessment.Next, fmt.Sprintf("Retry %d unavailable check(s) on the next patrol.", unknownCount))
		}
		return assessment
	}

	prev := make(map[string]CheckResult, len(previous.Checks))
	for _, check := range previous.Checks {
		prev[check.Key] = check
	}

	var changed []string
	for _, check := range current.Checks {
		old, ok := prev[check.Key]
		if !ok || old.Fingerprint != check.Fingerprint || old.Status != check.Status {
			changed = append(changed, check.Name)
		}
	}
	sort.Strings(changed)

	if len(changed) == 0 {
		assessment.Changes = []string{"No evidence category changed since the previous patrol."}
		assessment.Next = []string{"Continue scheduled patrols."}
	} else {
		assessment.Changes = []string{fmt.Sprintf("Observed changes in %d evidence categories since the previous patrol.", len(changed))}
		assessment.Next = []string{"Re-check changed categories on the next patrol."}
	}

	if unknownCount > 0 {
		assessment.Next = append(assessment.Next, fmt.Sprintf("Retry %d unavailable check(s).", unknownCount))
	}

	return assessment
}
