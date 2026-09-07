package patrol

import "time"

type Severity string

const (
	SeverityNormal  Severity = "normal"
	SeverityWarning Severity = "warning"
	SeverityDanger  Severity = "danger"
	SeverityUnknown Severity = "unknown"
)

type Check struct {
	Key      string   `json:"key"`
	Label    string   `json:"label"`
	Severity Severity `json:"severity"`
	Summary  string   `json:"summary"`
	Detail   string   `json:"detail,omitempty"`
}

type Report struct {
	ID         string    `json:"id"`
	Target     string    `json:"target"`
	StartedAt  time.Time `json:"started_at"`
	FinishedAt time.Time `json:"finished_at"`
	Status     Severity  `json:"status"`
	Checks     []Check   `json:"checks"`
	Assessment []string  `json:"assessment"`
	Next       []string  `json:"next"`
}

type Snapshot struct {
	Target    string            `json:"target"`
	Collected time.Time         `json:"collected"`
	Values    map[string]string `json:"values"`
	Evidence  map[string]string `json:"evidence"`
}
