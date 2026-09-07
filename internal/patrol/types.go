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

type Assessment struct {
	Status  Status   `json:"status"`
	Summary string   `json:"summary"`
	Changes []string `json:"changes"`
	Next    []string `json:"next"`
}

type PatrolReport struct {
	Snapshot   Snapshot   `json:"snapshot"`
	Assessment Assessment `json:"assessment"`
	Baseline   bool       `json:"baseline"`
}
