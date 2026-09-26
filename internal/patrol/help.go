package patrol

import (
	"fmt"
	"time"
)

type APIHelp struct {
	Name             string              `json:"name"`
	Purpose          string              `json:"purpose"`
	Entrypoint       string              `json:"entrypoint"`
	WebConsole       string              `json:"web_console"`
	Runtime          APIHelpRuntime      `json:"runtime"`
	Safety           APIHelpSafety       `json:"safety"`
	RecommendedFlow  []APIHelpFlowStep   `json:"recommended_agent_flow"`
	EndpointGroups   []APIHelpGroup      `json:"endpoint_groups"`
	CLI              []APIHelpCLIOption  `json:"cli_options"`
	Conventions      []string            `json:"conventions"`
}

type APIHelpRuntime struct {
	ListenAddress      string `json:"listen_address"`
	PatrolInterval     string `json:"patrol_interval"`
	PatrolTimeout      string `json:"patrol_timeout"`
	StructuredJournal string `json:"structured_journal"`
	MarkdownJournal   string `json:"markdown_journal_directory"`
	ServiceInterval   string `json:"service_interval,omitempty"`
	ServiceConfig     string `json:"service_config,omitempty"`
}

type APIHelpSafety struct {
	TargetHostPolicy    string   `json:"target_host_policy"`
	TargetMutations     bool     `json:"target_mutations"`
	LocalStateMutations []string `json:"local_state_mutations"`
	ForbiddenActions    []string `json:"forbidden_actions"`
	AccessControl       []string `json:"access_control"`
}

type APIHelpFlowStep struct {
	Step    int      `json:"step"`
	Action  string   `json:"action"`
	Why     string   `json:"why"`
	Details []string `json:"details,omitempty"`
}

type APIHelpGroup struct {
	Name      string            `json:"name"`
	Endpoints []APIHelpEndpoint `json:"endpoints"`
}

type APIHelpEndpoint struct {
	Method          string                    `json:"method"`
	Path            string                    `json:"path"`
	Summary         string                    `json:"summary"`
	TargetReadOnly  bool                      `json:"target_read_only"`
	MutatesOutpost  bool                      `json:"mutates_outpost"`
	Query           []APIHelpField            `json:"query,omitempty"`
	PathParameters  []APIHelpField            `json:"path_parameters,omitempty"`
	Body             []APIHelpField            `json:"body,omitempty"`
	Returns          string                    `json:"returns"`
	StatusCodes      map[string]string         `json:"status_codes,omitempty"`
	Notes            []string                  `json:"notes,omitempty"`
	ExampleBody      map[string]any            `json:"example_body,omitempty"`
}

type APIHelpField struct {
	Name        string `json:"name"`
	Type        string `json:"type"`
	Required    bool   `json:"required"`
	Default     string `json:"default,omitempty"`
	Maximum     string `json:"maximum,omitempty"`
	Description string `json:"description"`
}

type APIHelpCLIOption struct {
	Flag        string `json:"flag"`
	Default     string `json:"default"`
	Description string `json:"description"`
}

func (s *WebServer) buildAPIHelp() APIHelp {
	runtime := APIHelpRuntime{
		ListenAddress:      s.addr,
		PatrolInterval:     durationString(s.runner.cfg.Interval),
		PatrolTimeout:      durationString(s.runner.cfg.Timeout),
		StructuredJournal: s.runner.cfg.Journal,
		MarkdownJournal:   s.runner.AgentJournalDir(),
	}
	if s.services != nil {
		runtime.ServiceInterval = s.services.Interval().String()
		runtime.ServiceConfig = s.services.ConfigPath()
	}

	return APIHelp{
		Name:       "Outpost HTTP API",
		Purpose:    "Read-only infrastructure patrol, adaptive AI patrol context, Markdown patrol memory, and external HTTP/HTTPS service observation.",
		Entrypoint: "/api/help",
		WebConsole: "/",
		Runtime:    runtime,
		Safety: APIHelpSafety{
			TargetHostPolicy: "observe-only",
			TargetMutations:  false,
			LocalStateMutations: []string{
				"POST /api/journals writes a local Markdown patrol journal.",
				"POST /api/services adds a local service-monitor target and persists its configuration.",
				"DELETE /api/services/{id} removes a local service-monitor target.",
				"Service checks update local external-surface baselines and in-memory service history.",
			},
			ForbiddenActions: []string{
				"restart or stop target services",
				"install or remove packages",
				"modify target files",
				"change target accounts or credentials",
				"change target firewall rules",
				"perform automatic remediation",
			},
			AccessControl: []string{
				"Outpost currently has no built-in HTTP authentication or authorization layer.",
				"The default listen address is loopback-only (127.0.0.1:6877).",
				"If the listen address is exposed beyond loopback for phone/remote access, place Outpost behind a trusted tunnel, VPN, or authenticated reverse proxy.",
				"Treat service-target configuration and journal-write endpoints as local administrative capabilities.",
			},
		},
		RecommendedFlow: []APIHelpFlowStep{
			{
				Step: 1, Action: "GET /api/help",
				Why: "Discover the live Outpost contract, safety rules, endpoint shapes, and runtime paths before acting.",
			},
			{
				Step: 2, Action: "POST /api/patrols/run",
				Why: "Create a fresh structured local-host patrol before deciding what deserves deeper attention.",
			},
			{
				Step: 3, Action: "GET /api/agent/context",
				Why: "Receive recent patrol trends, repeated findings, prior journal carry-over, and an advisory patrol-depth hint.",
				Details: []string{
					"The depth hint is advisory; choose the actual read-only investigation yourself.",
					"Prefer current evidence and unresolved journal items over routine repetition.",
				},
			},
			{
				Step: 4, Action: "GET /api/journals/{id} as needed",
				Why: "Read full historical Markdown only when a journal preview or carry-over item is relevant.",
			},
			{
				Step: 5, Action: "Perform additional read-only investigation",
				Why: "Follow anomalies, trends, or exceptions beyond the fixed patrol checklist without modifying the target.",
			},
			{
				Step: 6, Action: "POST /api/journals",
				Why: "Persist what was checked, why it was chosen, what was skipped, findings, patterns, and next checks for future patrols.",
			},
		},
		EndpointGroups: []APIHelpGroup{
			{
				Name: "Discovery and status",
				Endpoints: []APIHelpEndpoint{
					{
						Method: "GET", Path: "/api/help",
						Summary: "Return this complete live API/agent usage guide.",
						TargetReadOnly: true, MutatesOutpost: false,
						Returns: "APIHelp object.",
						StatusCodes: map[string]string{"200": "help returned"},
					},
					{
						Method: "GET", Path: "/api/status",
						Summary: "Return the latest host patrol report, current server time, and latest service results when service monitoring is configured.",
						TargetReadOnly: true, MutatesOutpost: false,
						Returns: "Object with latest, time, and optional services.",
						StatusCodes: map[string]string{"200": "status returned"},
						Notes: []string{"latest may be null before the first host patrol completes."},
					},
				},
			},
			{
				Name: "Host patrol",
				Endpoints: []APIHelpEndpoint{
					{
						Method: "GET", Path: "/api/patrols",
						Summary: "List recent structured host patrol reports, newest first.",
						TargetReadOnly: true, MutatesOutpost: false,
						Query: []APIHelpField{
							{Name: "limit", Type: "integer", Default: "50", Maximum: "200", Description: "Maximum number of patrol reports to return; invalid or non-positive values fall back to 50."},
						},
						Returns: "Object with patrols and count.",
						StatusCodes: map[string]string{"200": "patrol list returned", "500": "journal read failed"},
					},
					{
						Method: "POST", Path: "/api/patrols/run",
						Summary: "Run one local host patrol immediately and append its structured report to the JSONL patrol journal.",
						TargetReadOnly: true, MutatesOutpost: true,
						Returns: "PatrolReport containing snapshot, assessment, and baseline flag.",
						StatusCodes: map[string]string{"200": "patrol completed", "500": "patrol or journal write failed"},
						Notes: []string{
							"Target observation is read-only; the Outpost structured journal is updated locally.",
							"Manual and scheduled patrol runs are serialized to prevent sequence races.",
						},
					},
					{
						Method: "GET", Path: "/api/review-packet",
						Summary: "Return a compact AI-review packet for the latest patrol, including bounded evidence only when relevant.",
						TargetReadOnly: true, MutatesOutpost: false,
						Returns: "ReviewPacket with target, OS, sequence, status, security risk, health/watch summaries, findings, next checks, and selected evidence excerpts.",
						StatusCodes: map[string]string{"200": "packet returned", "404": "no patrol has completed yet"},
						Notes: []string{"Evidence excerpts are truncated to keep AI review context bounded."},
					},
				},
			},
			{
				Name: "Autonomous AI patrol",
				Endpoints: []APIHelpEndpoint{
					{
						Method: "GET", Path: "/api/agent/context",
						Summary: "Return the bounded context intended for an external AI/Codex patrol agent.",
						TargetReadOnly: true, MutatesOutpost: false,
						Query: []APIHelpField{
							{Name: "patrols", Type: "integer", Default: "8", Maximum: "50", Description: "Number of recent structured patrols used for adaptive analysis."},
							{Name: "journals", Type: "integer", Default: "6", Maximum: "30", Description: "Number of recent Markdown journal summaries/previews included for carry-over."},
						},
						Returns: "Object with patrol autonomous context and, when configured, service targets/latest service results.",
						StatusCodes: map[string]string{"200": "context returned", "500": "patrol or journal history read failed"},
						Notes: []string{
							"Includes light/normal/focused/deep depth hint, recent patrol digests, signals, pending checks, guardrails, and workflow guidance.",
							"Full historical Markdown bodies are intentionally omitted; fetch a specific journal when needed.",
							"AI chooses the actual read-only patrol scope. Outpost signals are hints, not mandatory commands.",
						},
					},
				},
			},
			{
				Name: "Markdown patrol journals",
				Endpoints: []APIHelpEndpoint{
					{
						Method: "GET", Path: "/api/journals",
						Summary: "List Markdown patrol journal metadata and previews, newest first.",
						TargetReadOnly: true, MutatesOutpost: false,
						Query: []APIHelpField{
							{Name: "limit", Type: "integer", Default: "50", Maximum: "200", Description: "Maximum journal entries to return."},
						},
						Returns: "Object with journals, count, and Markdown journal directory.",
						StatusCodes: map[string]string{"200": "journal list returned", "500": "journal directory read failed"},
						Notes: []string{"Plain .md files manually placed in the journal directory are also discovered."},
					},
					{
						Method: "GET", Path: "/api/journals/{id}",
						Summary: "Return one Markdown patrol journal including its full Markdown body.",
						TargetReadOnly: true, MutatesOutpost: false,
						PathParameters: []APIHelpField{
							{Name: "id", Type: "string", Required: true, Description: "Journal id returned by GET /api/journals."},
						},
						Returns: "AgentJournalEntry including markdown.",
						StatusCodes: map[string]string{"200": "journal returned", "404": "journal not found", "500": "journal read failed"},
					},
					{
						Method: "POST", Path: "/api/journals",
						Summary: "Create a local free-form Markdown patrol journal for AI/human patrol memory.",
						TargetReadOnly: true, MutatesOutpost: true,
						Body: []APIHelpField{
							{Name: "title", Type: "string", Required: true, Description: "Journal title."},
							{Name: "markdown", Type: "string", Required: true, Maximum: fmt.Sprintf("%d bytes", maxAgentJournalBytes), Description: "Free-form Markdown body."},
							{Name: "status", Type: "string", Default: "note", Description: "One of note, normal, warning, danger, unknown."},
							{Name: "patrol_sequence", Type: "integer", Description: "Related patrol sequence; zero/omitted is automatically linked to the latest completed patrol when available."},
							{Name: "summary", Type: "string", Description: "Short list/UI summary."},
							{Name: "tags", Type: "string[]", Description: "Search/grouping tags."},
							{Name: "focus", Type: "string[]", Description: "Items deliberately investigated in this patrol."},
							{Name: "next", Type: "string[]", Description: "Carry-over checks that future autonomous patrol context should surface."},
						},
						Returns: "Created AgentJournalEntry including generated id, file name, timestamp, metadata, preview, and Markdown.",
						StatusCodes: map[string]string{"201": "journal created", "400": "invalid JSON, missing required field, unsupported status, or body too large"},
						ExampleBody: map[string]any{
							"title": "Docker storage follow-up",
							"status": "warning",
							"summary": "Container log growth remains above the recent baseline.",
							"tags": []string{"docker", "storage"},
							"focus": []string{"container logs", "disk growth"},
							"next": []string{"recheck growth rate on next patrol"},
							"markdown": "# Patrol note\n\n## Why this was checked\nRecent patrols showed sustained disk growth.\n\n## Result\nRead-only investigation completed.",
						},
					},
				},
			},
			{
				Name: "External service monitor",
				Endpoints: []APIHelpEndpoint{
					{
						Method: "GET", Path: "/api/services",
						Summary: "Return configured service targets, latest results, and up to 100 in-memory recent service results.",
						TargetReadOnly: true, MutatesOutpost: false,
						Returns: "Object with targets, latest, and history.",
						StatusCodes: map[string]string{"200": "service state returned", "503": "service monitor not configured"},
						Notes: []string{"Service history is in memory only; configured targets and their latest external-surface baselines are persisted."},
					},
					{
						Method: "POST", Path: "/api/services",
						Summary: "Add and persist an HTTP/HTTPS service-monitor target.",
						TargetReadOnly: true, MutatesOutpost: true,
						Body: []APIHelpField{
							{Name: "name", Type: "string", Required: true, Description: "Display name."},
							{Name: "url", Type: "string", Required: true, Description: "Valid http:// or https:// URL."},
							{Name: "expected_status", Type: "integer", Default: "200", Description: "Required HTTP response status."},
							{Name: "max_latency_ms", Type: "integer", Default: "1000", Description: "Latency above this value produces WARNING."},
							{Name: "body_contains", Type: "string", Description: "Optional substring that must occur in the first 64 KiB of response body."},
							{Name: "id", Type: "string", Description: "Optional explicit target id; generated when omitted."},
						},
						Returns: "Created service Target.",
						StatusCodes: map[string]string{"201": "target created", "400": "invalid target or duplicate id", "503": "service monitor not configured"},
						Notes: []string{
							"enabled is forced true when created.",
							"baseline supplied by the caller is discarded; the first successful check establishes the external-surface baseline.",
						},
						ExampleBody: map[string]any{
							"name": "FlowGate",
							"url": "https://example.com/health",
							"expected_status": 200,
							"max_latency_ms": 1000,
							"body_contains": "healthy",
						},
					},
					{
						Method: "POST", Path: "/api/services/run",
						Summary: "Run all enabled external service checks immediately.",
						TargetReadOnly: true, MutatesOutpost: true,
						Returns: "Object with results array.",
						StatusCodes: map[string]string{"200": "checks completed", "500": "check runner failed", "503": "service monitor not configured"},
						Notes: []string{
							"Checks DNS, TCP reachability, common exposed ports, TLS/certificate state for HTTPS, HTTP status, latency, body fingerprint, and optional response text.",
							"Successful checks update the persisted external-surface baseline; results are also appended to in-memory history.",
						},
					},
					{
						Method: "POST", Path: "/api/services/{id}/run",
						Summary: "Run one configured external service check immediately.",
						TargetReadOnly: true, MutatesOutpost: true,
						PathParameters: []APIHelpField{
							{Name: "id", Type: "string", Required: true, Description: "Service target id from GET /api/services."},
						},
						Returns: "Single service Result.",
						StatusCodes: map[string]string{"200": "check completed", "404": "service target not found", "503": "service monitor not configured"},
						Notes: []string{"A successful check may update the target's persisted external-surface baseline."},
					},
					{
						Method: "DELETE", Path: "/api/services/{id}",
						Summary: "Remove a local service-monitor target and its latest cached result.",
						TargetReadOnly: true, MutatesOutpost: true,
						PathParameters: []APIHelpField{
							{Name: "id", Type: "string", Required: true, Description: "Service target id."},
						},
						Returns: "Empty body.",
						StatusCodes: map[string]string{"204": "target removed", "404": "service target not found", "503": "service monitor not configured"},
						Notes: []string{"This changes Outpost configuration only; it does not alter the monitored service."},
					},
				},
			},
		},
		CLI: []APIHelpCLIOption{
			{Flag: "-listen", Default: "127.0.0.1:6877", Description: "Web console/API listen address."},
			{Flag: "-interval", Default: "1h", Description: "Local host patrol interval."},
			{Flag: "-timeout", Default: "30s", Description: "Maximum duration for a local host patrol."},
			{Flag: "-journal", Default: "outpost-journal.jsonl", Description: "Structured patrol JSONL journal path."},
			{Flag: "-md-journal-dir", Default: "outpost-journals", Description: "AI/autonomous patrol Markdown journal directory."},
			{Flag: "-service-interval", Default: "5m", Description: "External service monitor interval."},
			{Flag: "-service-timeout", Default: "10s", Description: "Per-target external service monitor timeout."},
			{Flag: "-service-config", Default: "outpost-services.json", Description: "Persisted external service target configuration path."},
		},
		Conventions: []string{
			"API responses are JSON except DELETE /api/services/{id}, which returns 204 with an empty body.",
			"Times are encoded by Go's time.Time JSON marshaler (RFC3339/RFC3339Nano form).",
			"Host patrol statuses: normal, warning, danger, unknown.",
			"Service statuses: up, warning, down, unknown.",
			"Journal statuses: note, normal, warning, danger, unknown.",
			"Invalid or non-positive bounded list/context query values fall back to their endpoint defaults; values above the documented maximum are clamped.",
			"The Web UI is served at GET / and is not required for API/agent use.",
		},
	}
}

func durationString(value time.Duration) string {
	if value <= 0 {
		return "not configured"
	}
	return value.String()
}
