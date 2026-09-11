package patrol

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/horrible-gh/Outpost/internal/monitor"
)

type WebServer struct {
	addr     string
	runner   *Runner
	services *monitor.Runner
	tmpl     *template.Template
}

type webPageData struct {
	Latest          *PatrolReport
	History         []PatrolReport
	ServiceTargets  []monitor.Target
	ServiceResults  []monitor.Result
	ServiceConfig   string
	ServiceInterval string
}

func NewWebServer(addr string, runner *Runner, serviceRunners ...*monitor.Runner) *WebServer {
	var services *monitor.Runner
	if len(serviceRunners) > 0 {
		services = serviceRunners[0]
	}
	functions := template.FuncMap{
		"upper":          func(value any) string { return strings.ToUpper(fmt.Sprint(value)) },
		"securityState":  securityState,
		"securityDetail": securityDetail,
	}
	return &WebServer{
		addr:     addr,
		runner:   runner,
		services: services,
		tmpl:     template.Must(template.New("index").Funcs(functions).Parse(indexHTML)),
	}
}

func (s *WebServer) Run(ctx context.Context) error {
	server := &http.Server{Addr: s.addr, Handler: s.Handler(), ReadHeaderTimeout: 5 * time.Second}
	errCh := make(chan error, 1)
	go func() { errCh <- server.ListenAndServe() }()
	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdownCtx); err != nil {
			return err
		}
		err := <-errCh
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case err := <-errCh:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
}

func (s *WebServer) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /", s.handleIndex)
	mux.HandleFunc("GET /api/status", s.handleStatus)
	mux.HandleFunc("GET /api/patrols", s.handlePatrols)
	mux.HandleFunc("GET /api/review-packet", s.handleReviewPacket)
	mux.HandleFunc("POST /api/patrols/run", s.handleRun)
	mux.HandleFunc("GET /api/services", s.handleServices)
	mux.HandleFunc("POST /api/services", s.handleAddService)
	mux.HandleFunc("POST /api/services/run", s.handleRunServices)
	mux.HandleFunc("POST /api/services/{id}/run", s.handleRunService)
	mux.HandleFunc("DELETE /api/services/{id}", s.handleDeleteService)
	return mux
}

func (s *WebServer) handleIndex(w http.ResponseWriter, r *http.Request) {
	history, err := s.runner.Recent(20)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	data := webPageData{Latest: s.runner.Latest(), History: history}
	if s.services != nil {
		data.ServiceTargets = s.services.Targets()
		data.ServiceResults = s.services.Latest()
		data.ServiceConfig = s.services.ConfigPath()
		data.ServiceInterval = s.services.Interval().String()
	}
	var buf bytes.Buffer
	if err := s.tmpl.Execute(&buf, data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(buf.Bytes())
}

func (s *WebServer) handleStatus(w http.ResponseWriter, r *http.Request) {
	payload := map[string]any{"latest": s.runner.Latest(), "time": time.Now()}
	if s.services != nil {
		payload["services"] = s.services.Latest()
	}
	writeJSON(w, http.StatusOK, payload)
}

func (s *WebServer) handlePatrols(w http.ResponseWriter, r *http.Request) {
	limit := 50
	if raw := r.URL.Query().Get("limit"); raw != "" {
		if parsed, err := strconv.Atoi(raw); err == nil && parsed > 0 {
			if parsed > 200 {
				parsed = 200
			}
			limit = parsed
		}
	}
	history, err := s.runner.Recent(limit)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"patrols": history, "count": len(history)})
}

func (s *WebServer) handleReviewPacket(w http.ResponseWriter, r *http.Request) {
	latest := s.runner.Latest()
	if latest == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "no patrol has completed yet"})
		return
	}
	writeJSON(w, http.StatusOK, BuildReviewPacket(*latest))
}

func (s *WebServer) handleRun(w http.ResponseWriter, r *http.Request) {
	report, err := s.runner.RunOnce(r.Context())
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, report)
}

func (s *WebServer) handleServices(w http.ResponseWriter, r *http.Request) {
	if !s.requireServices(w) {
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"targets": s.services.Targets(),
		"latest":  s.services.Latest(),
		"history": s.services.History(100),
	})
}

func (s *WebServer) handleAddService(w http.ResponseWriter, r *http.Request) {
	if !s.requireServices(w) {
		return
	}
	var target monitor.Target
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64*1024)).Decode(&target); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON: " + err.Error()})
		return
	}
	created, err := s.services.AddTarget(target)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusCreated, created)
}

func (s *WebServer) handleRunServices(w http.ResponseWriter, r *http.Request) {
	if !s.requireServices(w) {
		return
	}
	results, err := s.services.RunOnce(r.Context())
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"results": results})
}

func (s *WebServer) handleRunService(w http.ResponseWriter, r *http.Request) {
	if !s.requireServices(w) {
		return
	}
	result, err := s.services.RunTarget(r.Context(), r.PathValue("id"))
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (s *WebServer) handleDeleteService(w http.ResponseWriter, r *http.Request) {
	if !s.requireServices(w) {
		return
	}
	if err := s.services.RemoveTarget(r.PathValue("id")); err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": err.Error()})
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *WebServer) requireServices(w http.ResponseWriter) bool {
	if s.services != nil {
		return true
	}
	writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "service monitor is not configured"})
	return false
}

func securityState(result monitor.Result, kind string) string {
	if result.Status == monitor.StatusDown {
		return "unknown"
	}
	if result.SecurityBaseline {
		return "baseline"
	}
	if kind == "tls" && result.TLSFingerprint == "" {
		return "unknown"
	}
	for _, change := range result.SecurityChanges {
		lower := strings.ToLower(change)
		switch kind {
		case "dns":
			if strings.Contains(lower, "dns changed") {
				return "warning"
			}
		case "tls":
			if strings.Contains(lower, "tls certificate") {
				return "warning"
			}
		case "content":
			if strings.Contains(lower, "response body fingerprint") {
				return "warning"
			}
		case "ports":
			if strings.Contains(lower, "exposed port") || strings.Contains(lower, "no longer exposed") {
				return "warning"
			}
		}
	}
	return "normal"
}

func securityDetail(result monitor.Result, kind string) string {
	if result.Status == monitor.StatusDown {
		return "not compared while service is down"
	}
	for _, change := range result.SecurityChanges {
		lower := strings.ToLower(change)
		switch kind {
		case "dns":
			if strings.Contains(lower, "dns changed") {
				return change
			}
		case "tls":
			if strings.Contains(lower, "tls certificate") {
				return change
			}
		case "content":
			if strings.Contains(lower, "response body fingerprint") {
				return change
			}
		case "ports":
			if strings.Contains(lower, "exposed port") || strings.Contains(lower, "no longer exposed") {
				return change
			}
		}
	}
	if result.SecurityBaseline {
		return "baseline established"
	}
	switch kind {
	case "dns":
		if len(result.DNSAddresses) == 0 {
			return "no DNS result"
		}
		return strings.Join(result.DNSAddresses, ", ")
	case "tls":
		if result.TLSFingerprint == "" {
			return "not applicable"
		}
		if result.TLSIssuer != "" {
			return result.TLSIssuer
		}
		return "certificate unchanged"
	case "content":
		if result.BodySHA256 == "" {
			return "no fingerprint"
		}
		hash := result.BodySHA256
		if len(hash) > 16 {
			hash = hash[:16]
		}
		return "sha256 " + hash + "…"
	case "ports":
		if len(result.OpenPorts) == 0 {
			return "none detected"
		}
		values := make([]string, 0, len(result.OpenPorts))
		for _, port := range result.OpenPorts {
			values = append(values, strconv.Itoa(port))
		}
		return strings.Join(values, ", ")
	default:
		return ""
	}
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

const indexHTML = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Outpost</title>
<style>
:root{font-family:Inter,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;color:#1f2933;background:#eef2f5}*{box-sizing:border-box}body{margin:0}.wrap{max-width:1180px;margin:auto;padding:30px 22px 70px}.top{display:flex;justify-content:space-between;align-items:center;gap:20px;margin-bottom:16px}h1{font-size:34px;margin:0;letter-spacing:-.03em}.subtitle{color:#74808c;margin-top:3px}.tabs{display:flex;gap:6px;border-bottom:1px solid #d7dee4;margin-bottom:20px;overflow:auto}.tab{appearance:none;border:0;background:transparent;padding:12px 14px;color:#66727d;font-weight:750;cursor:pointer;border-bottom:3px solid transparent;white-space:nowrap}.tab.active{color:#17212b;border-bottom-color:#17212b}.panel{display:none}.panel.active{display:block}.actions{display:flex;gap:8px;flex-wrap:wrap}.btn{border:0;border-radius:9px;padding:10px 15px;background:#17212b;color:#fff;font-weight:700;cursor:pointer}.btn.secondary{background:#e8edf1;color:#28343f}.btn.danger-btn{background:#aa2525}.btn:disabled{opacity:.55}.card{background:#fff;border:1px solid #dfe5ea;border-radius:14px;padding:20px;margin-bottom:16px;box-shadow:0 1px 3px rgba(17,24,39,.04)}.cards{display:grid;grid-template-columns:repeat(3,1fr);gap:12px;margin-bottom:16px}.metric{background:#fff;border:1px solid #dfe5ea;border-radius:14px;padding:18px}.metric .value{font-size:26px;font-weight:800}.metric .label{font-size:12px;color:#75808a;margin-top:4px}.hostrow{display:flex;align-items:center;gap:10px;flex-wrap:wrap}.host{font-size:23px;font-weight:750}.badge{display:inline-block;padding:4px 9px;border-radius:999px;font-size:11px;font-weight:800;letter-spacing:.03em}.normal,.up{background:#e7f7ee;color:#147746}.warning{background:#fff2cc;color:#875800}.danger,.down{background:#fde7e7;color:#aa2525}.unknown{background:#edf0f3;color:#626b75}.baseline{background:#e9f0ff;color:#315fa8}.risk{background:#17212b;color:#fff}.meta{color:#78838d;font-size:13px;margin-top:6px}.section-title{font-size:12px;color:#73808b;text-transform:uppercase;letter-spacing:.08em;margin:2px 0 12px}.watch-grid,.health-grid{display:grid;grid-template-columns:repeat(4,1fr);gap:10px}.watch,.health{border:1px solid #e2e7eb;border-radius:10px;padding:12px;background:#fafbfc}.watch .n,.health .n{font-size:25px;font-weight:800}.watch .l,.health .l{font-size:11px;color:#75808a;margin-top:2px}.watch.alert .n,.health.alert .n{color:#a36500}.watch.danger-watch .n{color:#aa2525}.summary{font-size:15px;line-height:1.5}.cols{display:grid;grid-template-columns:1fr 1fr;gap:16px}.compact{margin:0;padding-left:18px}.compact li{margin:6px 0;line-height:1.4}.finding{border-left:3px solid #d7dde3;padding:8px 10px;margin:8px 0;background:#fafbfc;border-radius:0 8px 8px 0}.finding.warning{border-left-color:#d69a1d;background:#fffaf0}.finding.danger{border-left-color:#c83a3a;background:#fff5f5}table{width:100%;border-collapse:collapse;margin-top:8px}th,td{text-align:left;padding:10px 8px;border-bottom:1px solid #edf0f2;vertical-align:top}th{font-size:11px;color:#78838d;text-transform:uppercase;letter-spacing:.06em}details summary{cursor:pointer;color:#53606c}pre{white-space:pre-wrap;word-break:break-word;font-size:11px;background:#f6f8fa;padding:10px;border-radius:8px;max-height:260px;overflow:auto}.empty{text-align:center;color:#74808c;padding:40px}.history-row{display:grid;grid-template-columns:90px 1fr 100px 110px;gap:12px;align-items:center;padding:9px 0;border-bottom:1px solid #edf0f2}.history-row:last-child{border-bottom:0}.history-time{font-size:12px;color:#687480}.history-summary{white-space:nowrap;overflow:hidden;text-overflow:ellipsis;font-size:13px}.history-risk{text-align:right;font-size:12px;font-weight:700}.service-grid{display:grid;grid-template-columns:repeat(2,1fr);gap:12px}.service{border:1px solid #dfe5ea;border-radius:12px;padding:16px;background:#fff}.service-head{display:flex;justify-content:space-between;gap:12px;align-items:center}.service-name{font-weight:800;font-size:17px}.service-url{font-size:12px;color:#74808c;overflow-wrap:anywhere;margin-top:3px}.service-stats{display:grid;grid-template-columns:repeat(4,1fr);gap:8px;margin-top:14px}.stat{background:#f7f9fa;border-radius:8px;padding:9px}.stat strong{display:block;font-size:14px}.stat span{font-size:10px;color:#78838d}.service-summary{font-size:13px;margin-top:12px;color:#56626d}.security-box{margin-top:14px;padding-top:14px;border-top:1px solid #e7ebee}.security-head{display:flex;align-items:center;justify-content:space-between;gap:8px;margin-bottom:9px}.security-title{font-size:11px;font-weight:800;color:#687480;text-transform:uppercase;letter-spacing:.07em}.security-grid{display:grid;grid-template-columns:repeat(2,1fr);gap:8px}.security-item{border:1px solid #e2e7eb;border-radius:9px;padding:9px;background:#fafbfc;min-width:0}.security-item .security-row{display:flex;align-items:center;justify-content:space-between;gap:6px}.security-item strong{font-size:12px}.security-detail{font-size:10px;color:#75808a;margin-top:5px;line-height:1.35;overflow-wrap:anywhere}.form-grid{display:grid;grid-template-columns:1fr 2fr 1fr 1fr;gap:10px}.field label{display:block;font-size:11px;font-weight:750;color:#687480;margin-bottom:5px}.field input{width:100%;border:1px solid #cfd7de;border-radius:8px;padding:10px;background:#fff}.hint{font-size:12px;color:#74808c;line-height:1.5}.target-list{margin-top:18px}.target-row{display:grid;grid-template-columns:1fr 2fr auto;gap:10px;align-items:center;padding:10px 0;border-top:1px solid #edf0f2}.target-row:first-child{border-top:0}@media(max-width:850px){.watch-grid,.health-grid{grid-template-columns:repeat(2,1fr)}.cols,.service-grid,.cards{grid-template-columns:1fr}.service-stats,.security-grid{grid-template-columns:repeat(2,1fr)}.form-grid{grid-template-columns:1fr}.history-row{grid-template-columns:72px 1fr 72px}.history-summary{display:none}.target-row{grid-template-columns:1fr}}
</style>
</head>
<body><div class="wrap">
<div class="top"><div><h1>Outpost</h1><div class="subtitle">Infrastructure patrol console</div></div></div>
<div class="tabs"><button class="tab active" data-tab="overview">Overview</button><button class="tab" data-tab="host">Host Patrol</button><button class="tab" data-tab="services">Service Monitor</button><button class="tab" data-tab="settings">Settings</button></div>

<section id="overview" class="panel active">
<div class="cards">
<div class="metric"><div class="value">{{with .Latest}}{{upper .Assessment.Status}}{{else}}UNKNOWN{{end}}</div><div class="label">Host Patrol</div></div>
<div class="metric"><div class="value" id="service-health">{{len .ServiceResults}} checked</div><div class="label">External Services</div></div>
<div class="metric"><div class="value">{{len .ServiceTargets}}</div><div class="label">Configured Targets</div></div>
</div>
{{with .Latest}}<div class="card"><div class="section-title">Latest Host Assessment</div><div class="hostrow"><span class="host">{{.Snapshot.Target}}</span><span class="badge {{.Assessment.Status}}">{{upper .Assessment.Status}}</span><span class="badge risk">SECURITY RISK {{.Assessment.RiskScore}}/100</span></div><div class="meta">Patrol #{{.Snapshot.Sequence}} · {{.Snapshot.StartedAt.Format "2006-01-02 15:04:05"}}</div><div class="summary" style="margin-top:12px">{{.Assessment.Summary}}</div></div>{{end}}
{{if .ServiceResults}}<div class="card"><div class="section-title">External Services</div><table><thead><tr><th>Service</th><th>Status</th><th>HTTP</th><th>Latency</th><th>Last check</th></tr></thead><tbody>{{range .ServiceResults}}<tr><td><strong>{{.Name}}</strong><div class="service-url">{{.URL}}</div></td><td><span class="badge {{.Status}}">{{upper .Status}}</span></td><td>{{.HTTPStatus}}</td><td>{{.LatencyMS}} ms</td><td>{{.CheckedAt.Format "01-02 15:04:05"}}</td></tr>{{end}}</tbody></table></div>{{end}}
</section>

<section id="host" class="panel">
<div class="actions" style="margin-bottom:16px"><button class="btn" id="patrol-btn" onclick="runPatrol()">Run patrol now</button></div>
{{with .Latest}}<div class="card"><div class="hostrow"><span class="host">{{.Snapshot.Target}}</span><span class="badge {{.Assessment.Status}}">{{upper .Assessment.Status}}</span><span class="badge risk">SECURITY RISK {{.Assessment.RiskScore}}/100</span>{{if .Baseline}}<span class="badge baseline">BASELINE</span>{{end}}</div><div class="meta">Patrol #{{.Snapshot.Sequence}} · {{.Snapshot.StartedAt.Format "2006-01-02 15:04:05"}} · {{.Snapshot.OS}}</div></div>
<div class="card"><div class="section-title">Host Health</div><div class="health-grid"><div class="health"><div class="n">{{printf "%.1f" .Assessment.Health.CPUPercent}}%</div><div class="l">CPU</div></div><div class="health"><div class="n">{{printf "%.1f" .Assessment.Health.MemoryPercent}}%</div><div class="l">Memory</div></div><div class="health"><div class="n">{{printf "%.1f" .Assessment.Health.SwapPercent}}%</div><div class="l">Swap</div></div><div class="health {{if .Assessment.Watch.ResourceHeavyProcesses}}alert{{end}}"><div class="n">{{.Assessment.Watch.ResourceHeavyProcesses}}</div><div class="l">Heavy processes</div></div></div></div>
<div class="card"><div class="section-title">Security Watch</div><div class="watch-grid"><div class="watch {{if .Assessment.Watch.NewListeners}}alert{{end}}"><div class="n">{{.Assessment.Watch.NewListeners}}</div><div class="l">New listeners</div></div><div class="watch {{if .Assessment.Watch.FailedLogins}}alert{{end}}"><div class="n">{{.Assessment.Watch.FailedLogins}}</div><div class="l">Failed logins</div></div><div class="watch {{if .Assessment.Watch.NewUsers}}alert{{end}}"><div class="n">{{.Assessment.Watch.NewUsers}}</div><div class="l">New users</div></div><div class="watch {{if .Assessment.Watch.NewServices}}alert{{end}}"><div class="n">{{.Assessment.Watch.NewServices}}</div><div class="l">New services</div></div><div class="watch {{if .Assessment.Watch.SuspiciousProcesses}}alert{{end}}"><div class="n">{{.Assessment.Watch.SuspiciousProcesses}}</div><div class="l">Suspicious processes</div></div><div class="watch {{if .Assessment.Watch.UnusualConnections}}alert{{end}}"><div class="n">{{.Assessment.Watch.UnusualConnections}}</div><div class="l">Unusual connections</div></div><div class="watch {{if .Assessment.Watch.ThreatDetections}}danger-watch{{end}}"><div class="n">{{.Assessment.Watch.ThreatDetections}}</div><div class="l">Defender threats (24h)</div></div><div class="watch {{if .Assessment.Watch.ProtectionIssues}}danger-watch{{end}}"><div class="n">{{.Assessment.Watch.ProtectionIssues}}</div><div class="l">Protection issues</div></div></div></div>
<div class="card"><div class="section-title">Assessment</div><div class="summary">{{.Assessment.Summary}}</div>{{if .Assessment.Findings}}<div class="section-title" style="margin-top:18px">Findings</div>{{range .Assessment.Findings}}<div class="finding {{.Severity}}"><div class="cat">{{.Category}} · {{upper .Severity}}</div><div>{{.Message}}</div></div>{{end}}{{end}}<div class="cols"><div><div class="section-title" style="margin-top:18px">Changes</div><ul class="compact">{{range .Assessment.Changes}}<li>{{.}}</li>{{end}}</ul></div><div><div class="section-title" style="margin-top:18px">Next</div><ul class="compact">{{range .Assessment.Next}}<li>{{.}}</li>{{end}}</ul></div></div></div>
<div class="card"><div class="section-title">Evidence</div><table><thead><tr><th>Check</th><th>Status</th><th>Summary</th><th>Raw</th></tr></thead><tbody>{{range .Snapshot.Checks}}<tr><td>{{.Name}}</td><td><span class="badge {{.Status}}">{{upper .Status}}</span></td><td>{{.Summary}}</td><td>{{if .Raw}}<details><summary>View</summary><pre>{{.Raw}}</pre></details>{{else}}—{{end}}</td></tr>{{end}}</tbody></table></div>{{else}}<div class="card empty">No patrol has completed yet.</div>{{end}}
{{if .History}}<div class="card"><div class="section-title">Recent Patrols</div>{{range .History}}<div class="history-row"><div><strong>#{{.Snapshot.Sequence}}</strong><div class="history-time">{{.Snapshot.StartedAt.Format "01-02 15:04"}}</div></div><div class="history-summary">{{.Assessment.Summary}}</div><div><span class="badge {{.Assessment.Status}}">{{upper .Assessment.Status}}</span></div><div class="history-risk">SEC RISK {{.Assessment.RiskScore}}</div></div>{{end}}</div>{{end}}
</section>

<section id="services" class="panel">
<div class="actions" style="margin-bottom:16px"><button class="btn" id="service-btn" onclick="runServices()">Check all services</button><button class="btn secondary" onclick="showTab('settings')">Add service</button></div>
{{if .ServiceResults}}<div class="service-grid">{{range .ServiceResults}}<div class="service"><div class="service-head"><div><div class="service-name">{{.Name}}</div><div class="service-url">{{.URL}}</div></div><span class="badge {{.Status}}">{{upper .Status}}</span></div><div class="service-stats"><div class="stat"><strong>{{.HTTPStatus}}</strong><span>HTTP</span></div><div class="stat"><strong>{{.LatencyMS}} ms</strong><span>Latency</span></div><div class="stat"><strong>{{if .TCPReachable}}OK{{else}}FAIL{{end}}</strong><span>TCP</span></div><div class="stat"><strong>{{if .TLSExpiresAt.IsZero}}—{{else}}{{.TLSDaysLeft}} d{{end}}</strong><span>TLS left</span></div></div><div class="security-box"><div class="security-head"><div class="security-title">External Security</div>{{if .SecurityBaseline}}<span class="badge baseline">BASELINE ESTABLISHED</span>{{else if .SecurityChanges}}<span class="badge warning">{{len .SecurityChanges}} CHANGE(S)</span>{{else}}<span class="badge normal">STABLE</span>{{end}}</div><div class="security-grid"><div class="security-item"><div class="security-row"><strong>DNS</strong><span class="badge {{securityState . "dns"}}">{{upper (securityState . "dns")}}</span></div><div class="security-detail">{{securityDetail . "dns"}}</div></div><div class="security-item"><div class="security-row"><strong>TLS certificate</strong><span class="badge {{securityState . "tls"}}">{{upper (securityState . "tls")}}</span></div><div class="security-detail">{{securityDetail . "tls"}}</div></div><div class="security-item"><div class="security-row"><strong>Content fingerprint</strong><span class="badge {{securityState . "content"}}">{{upper (securityState . "content")}}</span></div><div class="security-detail">{{securityDetail . "content"}}</div></div><div class="security-item"><div class="security-row"><strong>Exposed ports</strong><span class="badge {{securityState . "ports"}}">{{upper (securityState . "ports")}}</span></div><div class="security-detail">{{securityDetail . "ports"}}</div></div></div></div><div class="service-summary">{{.Summary}}{{if .Error}} · {{.Error}}{{end}}</div><div class="meta">{{.CheckedAt.Format "2006-01-02 15:04:05"}}</div></div>{{end}}</div>{{else}}<div class="card empty">No service checks yet. Add a target in Settings, then run a check.</div>{{end}}
</section>

<section id="settings" class="panel">
<div class="card"><div class="section-title">Service Monitor</div><div class="hint">Targets are stored in <strong>{{if .ServiceConfig}}{{.ServiceConfig}}{{else}}outpost-services.json{{end}}</strong>. Default check interval: <strong>{{if .ServiceInterval}}{{.ServiceInterval}}{{else}}5m{{end}}</strong>. Each HTTP/HTTPS target checks DNS, TCP reachability, TLS (HTTPS), HTTP status, response latency, optional response content, and compares DNS/TLS/content/port exposure against the previous security baseline.</div></div>
<div class="card"><div class="section-title">Add External Service</div><div class="form-grid"><div class="field"><label>Name</label><input id="svc-name" placeholder="FlowGate"></div><div class="field"><label>URL</label><input id="svc-url" placeholder="https://example.com/health"></div><div class="field"><label>Expected HTTP</label><input id="svc-status" type="number" value="200"></div><div class="field"><label>Max latency (ms)</label><input id="svc-latency" type="number" value="1000"></div></div><div class="field" style="margin-top:10px"><label>Body contains (optional)</label><input id="svc-body" placeholder="healthy"></div><div class="actions" style="margin-top:12px"><button class="btn" onclick="addService()">Add service</button></div></div>
<div class="card"><div class="section-title">Configured Services</div>{{if .ServiceTargets}}<div class="target-list">{{range .ServiceTargets}}<div class="target-row"><div><strong>{{.Name}}</strong></div><div class="service-url">{{.URL}}</div><div class="actions"><button class="btn secondary" onclick="runOneService('{{.ID}}')">Check</button><button class="btn danger-btn" onclick="deleteService('{{.ID}}','{{.Name}}')">Delete</button></div></div>{{end}}</div>{{else}}<div class="empty">No external service targets configured.</div>{{end}}</div>
</section>
</div>
<script>
function showTab(id){document.querySelectorAll('.panel').forEach(x=>x.classList.toggle('active',x.id===id));document.querySelectorAll('.tab').forEach(x=>x.classList.toggle('active',x.dataset.tab===id));history.replaceState(null,'','#'+id)}
document.querySelectorAll('.tab').forEach(x=>x.addEventListener('click',()=>showTab(x.dataset.tab)));if(location.hash&&document.querySelector(location.hash))showTab(location.hash.slice(1));
async function runPatrol(){const b=document.getElementById('patrol-btn');b.disabled=true;b.textContent='Patrolling…';try{const r=await fetch('/api/patrols/run',{method:'POST'});if(!r.ok)throw new Error(await r.text());location.hash='host';location.reload()}catch(e){alert('Patrol failed: '+e.message);b.disabled=false;b.textContent='Run patrol now'}}
async function runServices(){const b=document.getElementById('service-btn');b.disabled=true;b.textContent='Checking…';try{const r=await fetch('/api/services/run',{method:'POST'});if(!r.ok)throw new Error(await r.text());location.hash='services';location.reload()}catch(e){alert('Service check failed: '+e.message);b.disabled=false;b.textContent='Check all services'}}
async function runOneService(id){try{const r=await fetch('/api/services/'+encodeURIComponent(id)+'/run',{method:'POST'});if(!r.ok)throw new Error(await r.text());location.hash='services';location.reload()}catch(e){alert('Service check failed: '+e.message)}}
async function addService(){const payload={name:document.getElementById('svc-name').value,url:document.getElementById('svc-url').value,expected_status:Number(document.getElementById('svc-status').value||200),max_latency_ms:Number(document.getElementById('svc-latency').value||1000),body_contains:document.getElementById('svc-body').value};try{const r=await fetch('/api/services',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(payload)});if(!r.ok)throw new Error(await r.text());location.hash='settings';location.reload()}catch(e){alert('Add service failed: '+e.message)}}
async function deleteService(id,name){if(!confirm('Delete service '+name+'?'))return;try{const r=await fetch('/api/services/'+encodeURIComponent(id),{method:'DELETE'});if(!r.ok)throw new Error(await r.text());location.hash='settings';location.reload()}catch(e){alert('Delete service failed: '+e.message)}}
</script></body></html>`

func (s *WebServer) String() string { return fmt.Sprintf("Outpost web server (%s)", s.addr) }
