package patrol

import "testing"

func reviewReport(seq int64, status Status, risk int) PatrolReport {
	return PatrolReport{Snapshot: Snapshot{Sequence: seq}, Assessment: Assessment{Status: status, RiskScore: risk}}
}

func TestReviewPolicyWarningMode(t *testing.T) {
	if DecideAIReview(reviewReport(1, StatusNormal, 0), ReviewPolicy{Mode: ReviewWarning}).Required { t.Fatal("normal patrol should not review") }
	if !DecideAIReview(reviewReport(2, StatusWarning, 0), ReviewPolicy{Mode: ReviewWarning}).Required { t.Fatal("warning patrol should review") }
}

func TestReviewPolicyPeriodicMode(t *testing.T) {
	policy := ReviewPolicy{Mode: ReviewPeriodic, EveryN: 6}
	if DecideAIReview(reviewReport(5, StatusNormal, 0), policy).Required { t.Fatal("sequence 5 should not review") }
	if !DecideAIReview(reviewReport(6, StatusNormal, 0), policy).Required { t.Fatal("sequence 6 should review") }
}

func TestReviewPolicyHybridMode(t *testing.T) {
	policy := ReviewPolicy{Mode: ReviewHybrid, EveryN: 12, MinimumRisk: 25}
	if !DecideAIReview(reviewReport(2, StatusWarning, 0), policy).Required { t.Fatal("warning should trigger") }
	if !DecideAIReview(reviewReport(3, StatusNormal, 30), policy).Required { t.Fatal("risk threshold should trigger") }
	if !DecideAIReview(reviewReport(12, StatusNormal, 0), policy).Required { t.Fatal("periodic interval should trigger") }
	if DecideAIReview(reviewReport(4, StatusNormal, 0), policy).Required { t.Fatal("quiet patrol should not trigger") }
}

func TestReviewPolicyOffAndAlways(t *testing.T) {
	if DecideAIReview(reviewReport(1, StatusDanger, 100), ReviewPolicy{Mode: ReviewOff}).Required { t.Fatal("off must never review") }
	if !DecideAIReview(reviewReport(1, StatusNormal, 0), ReviewPolicy{Mode: ReviewAlways}).Required { t.Fatal("always must review") }
}
