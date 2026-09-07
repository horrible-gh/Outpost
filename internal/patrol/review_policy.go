package patrol

import "strings"

type ReviewMode string

const (
	ReviewOff      ReviewMode = "off"
	ReviewAlways   ReviewMode = "always"
	ReviewWarning  ReviewMode = "warning"
	ReviewPeriodic ReviewMode = "periodic"
	ReviewHybrid   ReviewMode = "hybrid"
)

type ReviewPolicy struct {
	Mode        ReviewMode `json:"mode"`
	EveryN      int        `json:"every_n,omitempty"`
	MinimumRisk int        `json:"minimum_risk,omitempty"`
}

type ReviewDecision struct {
	Required bool   `json:"required"`
	Reason   string `json:"reason"`
}

func DecideAIReview(report PatrolReport, policy ReviewPolicy) ReviewDecision {
	mode := ReviewMode(strings.ToLower(string(policy.Mode)))
	if mode == "" { mode = ReviewWarning }
	if policy.MinimumRisk < 0 { policy.MinimumRisk = 0 }

	warning := report.Assessment.Status == StatusWarning || report.Assessment.Status == StatusDanger
	risky := policy.MinimumRisk > 0 && report.Assessment.RiskScore >= policy.MinimumRisk
	periodic := policy.EveryN > 0 && report.Snapshot.Sequence > 0 && report.Snapshot.Sequence%int64(policy.EveryN) == 0

	switch mode {
	case ReviewOff:
		return ReviewDecision{Reason: "AI review is disabled."}
	case ReviewAlways:
		return ReviewDecision{Required: true, Reason: "Policy reviews every patrol."}
	case ReviewPeriodic:
		if periodic { return ReviewDecision{Required: true, Reason: "Periodic review interval reached."} }
		return ReviewDecision{Reason: "Periodic review interval not reached."}
	case ReviewHybrid:
		if warning { return ReviewDecision{Required: true, Reason: "Patrol status requires review."} }
		if risky { return ReviewDecision{Required: true, Reason: "Security risk threshold reached."} }
		if periodic { return ReviewDecision{Required: true, Reason: "Periodic review interval reached."} }
		return ReviewDecision{Reason: "No review trigger matched."}
	case ReviewWarning:
		fallthrough
	default:
		if warning { return ReviewDecision{Required: true, Reason: "Patrol status requires review."} }
		if risky { return ReviewDecision{Required: true, Reason: "Security risk threshold reached."} }
		return ReviewDecision{Reason: "Patrol is below review threshold."}
	}
}
