package patrol

import "time"

type Status string

const (
	StatusNormal  Status = "normal"
	StatusWarning Status = "warning"
	StatusDanger  Status = "danger"
	StatusUnknown Status = "unknown"
)

type CheckResult struct {
	Key         string `json:"key"`
	Name        string `json:"name"`
	Status      Status `json:"status"`
	Summary     string `json:"summary"`
	Raw         string `json:"raw,omitempty"`
	Fingerprint string `json:"fingerprint"`
}

type Snapshot struct {
	Sequence   int64         `json:"sequence"`
	Target     string        `json:"target"`
	OS         string        `json:"os"`
	StartedAt  time.Time     `json:"started_at"`
	FinishedAt time.Time     `json:"finished_at"`
	Checks     []CheckResult `json:"checks"`
}

type WatchSummary struct {
	NewListeners        int `json:"new_listeners"`
	FailedLogins        int `json:"failed_logins"`
	NewUsers            int `json:"new_users"`
	NewServices         int `json:"new_services"`
	SuspiciousProcesses int `json:"suspicious_processes"`
	UnusualConnections  int `json:"unusual_connections"`
	ThreatDetections    int `json:"threat_detections"`
	ProtectionIssues    int `json:"protection_issues"`
}

type Assessment struct {
	Status  Status       `json:"status"`
	Summary string       `json:"summary"`
	Changes []string     `json:"changes"`
	Next    []string     `json:"next"`
	Watch   WatchSummary `json:"watch"`
}

type PatrolReport struct {
	Snapshot   Snapshot   `json:"snapshot"`
	Assessment Assessment `json:"assessment"`
	Baseline   bool       `json:"baseline"`
}
