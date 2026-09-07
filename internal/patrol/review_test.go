package patrol

import (
	"strings"
	"testing"
)

func TestReviewPacketOmitsRoutineEvidence(t *testing.T) {
	report := PatrolReport{
		Snapshot: Snapshot{Target: "host", OS: "windows", Sequence: 2, Checks: []CheckResult{
			{Key: "disk", Status: StatusNormal, Summary: "collected", Raw: strings.Repeat("x", 5000)},
			{Key: "network", Status: StatusNormal, Summary: "collected", Raw: "normal network evidence"},
		}},
		Assessment: Assessment{Status: StatusNormal, RiskScore: 0},
	}
	packet := BuildReviewPacket(report)
	if len(packet.Evidence) != 0 { t.Fatalf("expected no routine evidence, got %#v", packet.Evidence) }
}

func TestReviewPacketIncludesOnlyRelevantEvidenceAndTruncates(t *testing.T) {
	long := strings.Repeat("z", 3000)
	report := PatrolReport{
		Snapshot: Snapshot{Target: "host", OS: "windows", Sequence: 3, Checks: []CheckResult{
			{Key: "disk", Status: StatusNormal, Summary: "collected", Raw: "routine"},
			{Key: "network", Status: StatusNormal, Summary: "collected", Raw: long},
			{Key: "failed_logins", Status: StatusUnknown, Summary: "check unavailable", Raw: "access denied"},
		}},
		Assessment: Assessment{
			Status: StatusWarning, RiskScore: 10,
			Watch: WatchSummary{NewListeners: 1},
			Findings: []Finding{{Category: "exposure", Severity: StatusWarning, Message: "new listener"}},
		},
	}
	packet := BuildReviewPacket(report)
	if len(packet.Evidence) != 2 { t.Fatalf("expected network and failed login evidence, got %#v", packet.Evidence) }
	if packet.Evidence[0].Key != "network" { t.Fatalf("expected network first, got %s", packet.Evidence[0].Key) }
	if len(packet.Evidence[0].Excerpt) > 1603 { t.Fatalf("expected truncated excerpt, got length %d", len(packet.Evidence[0].Excerpt)) }
	if packet.Evidence[1].Key != "failed_logins" { t.Fatalf("expected unavailable check evidence, got %s", packet.Evidence[1].Key) }
}
