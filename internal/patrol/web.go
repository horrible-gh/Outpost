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
)

type WebServer struct { addr string; runner *Runner; tmpl *template.Template }
type webPageData struct { Latest *PatrolReport; History []PatrolReport }

func NewWebServer(addr string, runner *Runner) *WebServer {
	return &WebServer{addr: addr, runner: runner, tmpl: template.Must(template.New("index").Funcs(template.FuncMap{"upper": func(status Status) string { return strings.ToUpper(string(status)) }}).Parse(indexHTML))}
}

func (s *WebServer) Run(ctx context.Context) error {
	server := &http.Server{Addr: s.addr, Handler: s.Handler(), ReadHeaderTimeout: 5 * time.Second}
	errCh := make(chan error, 1); go func() { errCh <- server.ListenAndServe() }()
	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second); defer cancel()
		if err := server.Shutdown(shutdownCtx); err != nil { return err }
		err := <-errCh; if errors.Is(err, http.ErrServerClosed) { return nil }; return err
	case err := <-errCh:
		if errors.Is(err, http.ErrServerClosed) { return nil }; return err
	}
}

func (s *WebServer) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /", s.handleIndex)
	mux.HandleFunc("GET /api/status", s.handleStatus)
	mux.HandleFunc("GET /api/patrols", s.handlePatrols)
	mux.HandleFunc("GET /api/review-packet", s.handleReviewPacket)
	mux.HandleFunc("POST /api/patrols/run", s.handleRun)
	return mux
}

func (s *WebServer) handleIndex(w http.ResponseWriter, r *http.Request) {
	history, err := s.runner.Recent(20); if err != nil { http.Error(w, err.Error(), http.StatusInternalServerError); return }
	data := webPageData{Latest: s.runner.Latest(), History: history}
	var buf bytes.Buffer; if err := s.tmpl.Execute(&buf, data); err != nil { http.Error(w, err.Error(), http.StatusInternalServerError); return }
	w.Header().Set("Content-Type", "text/html; charset=utf-8"); _, _ = w.Write(buf.Bytes())
}
func (s *WebServer) handleStatus(w http.ResponseWriter, r *http.Request) { writeJSON(w, http.StatusOK, map[string]any{"latest": s.runner.Latest(), "time": time.Now()}) }
func (s *WebServer) handlePatrols(w http.ResponseWriter, r *http.Request) {
	limit := 50
	if raw := r.URL.Query().Get("limit"); raw != "" { if parsed, err := strconv.Atoi(raw); err == nil && parsed > 0 { if parsed > 200 { parsed = 200 }; limit = parsed } }
	history, err := s.runner.Recent(limit); if err != nil { writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()}); return }
	writeJSON(w, http.StatusOK, map[string]any{"patrols": history, "count": len(history)})
}
func (s *WebServer) handleReviewPacket(w http.ResponseWriter, r *http.Request) { latest := s.runner.Latest(); if latest == nil { writeJSON(w, http.StatusNotFound, map[string]string{"error":"no patrol has completed yet"}); return }; writeJSON(w, http.StatusOK, BuildReviewPacket(*latest)) }
func (s *WebServer) handleRun(w http.ResponseWriter, r *http.Request) { report, err := s.runner.RunOnce(r.Context()); if err != nil { writeJSON(w, http.StatusInternalServerError, map[string]string{"error":err.Error()}); return }; writeJSON(w, http.StatusOK, report) }
func writeJSON(w http.ResponseWriter, status int, value any) { w.Header().Set("Content-Type", "application/json; charset=utf-8"); w.WriteHeader(status); _ = json.NewEncoder(w).Encode(value) }

const indexHTML = `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Outpost</title><style>
:root{font-family:Inter,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;color:#1f2933;background:#eef2f5}*{box-sizing:border-box}body{margin:0}.wrap{max-width:1120px;margin:auto;padding:34px 22px 70px}.top{display:flex;justify-content:space-between;align-items:center;gap:20px;margin-bottom:24px}h1{font-size:34px;margin:0;letter-spacing:-.03em}.subtitle{color:#74808c;margin-top:3px}.btn{border:0;border-radius:9px;padding:11px 17px;background:#17212b;color:#fff;font-weight:700;cursor:pointer}.card{background:#fff;border:1px solid #dfe5ea;border-radius:14px;padding:20px;margin-bottom:16px;box-shadow:0 1px 3px rgba(17,24,39,.04)}.hostrow{display:flex;align-items:center;gap:10px;flex-wrap:wrap}.host{font-size:23px;font-weight:750}.badge{display:inline-block;padding:4px 9px;border-radius:999px;font-size:11px;font-weight:800;letter-spacing:.03em}.normal{background:#e7f7ee;color:#147746}.warning{background:#fff2cc;color:#875800}.danger{background:#fde7e7;color:#aa2525}.unknown{background:#edf0f3;color:#626b75}.baseline{background:#e9f0ff;color:#315fa8}.risk{background:#17212b;color:#fff}.meta{color:#78838d;font-size:13px;margin-top:6px}.section-title{font-size:12px;color:#73808b;text-transform:uppercase;letter-spacing:.08em;margin:2px 0 12px}.watch-grid{display:grid;grid-template-columns:repeat(4,1fr);gap:10px}.health-grid{display:grid;grid-template-columns:repeat(4,1fr);gap:10px}.watch,.health{border:1px solid #e2e7eb;border-radius:10px;padding:12px;background:#fafbfc}.watch .n,.health .n{font-size:25px;font-weight:800}.watch .l,.health .l{font-size:11px;color:#75808a;margin-top:2px}.watch.alert .n,.health.alert .n{color:#a36500}.watch.danger-watch .n{color:#aa2525}.summary{font-size:15px;line-height:1.5}.cols{display:grid;grid-template-columns:1fr 1fr;gap:16px}.compact{margin:0;padding-left:18px}.compact li{margin:6px 0;line-height:1.4}.finding{border-left:3px solid #d7dde3;padding:8px 10px;margin:8px 0;background:#fafbfc;border-radius:0 8px 8px 0}.finding.warning{border-left-color:#d69a1d;background:#fffaf0}.finding.danger{border-left-color:#c83a3a;background:#fff5f5}.finding .cat{font-size:10px;text-transform:uppercase;letter-spacing:.08em;color:#75808a;font-weight:800;margin-bottom:3px}table{width:100%;border-collapse:collapse;margin-top:8px}th,td{text-align:left;padding:10px 8px;border-bottom:1px solid #edf0f2;vertical-align:top}th{font-size:11px;color:#78838d;text-transform:uppercase;letter-spacing:.06em}details summary{cursor:pointer;color:#53606c}pre{white-space:pre-wrap;word-break:break-word;font-size:11px;background:#f6f8fa;padding:10px;border-radius:8px;max-height:260px;overflow:auto}.empty{text-align:center;color:#74808c;padding:40px}.history-row{display:grid;grid-template-columns:90px 1fr 100px 110px;gap:12px;align-items:center;padding:9px 0;border-bottom:1px solid #edf0f2}.history-row:last-child{border-bottom:0}.history-time{font-size:12px;color:#687480}.history-summary{white-space:nowrap;overflow:hidden;text-overflow:ellipsis;font-size:13px}.history-risk{text-align:right;font-size:12px;font-weight:700}@media(max-width:800px){.watch-grid,.health-grid{grid-template-columns:repeat(2,1fr)}.cols{grid-template-columns:1fr}.history-row{grid-template-columns:72px 1fr 72px}.history-summary{display:none}}
</style></head><body><div class="wrap"><div class="top"><div><h1>Outpost</h1><div class="subtitle">Server patrol journal</div></div><button class="btn" onclick="runPatrol()">Run patrol now</button></div>
{{with .Latest}}<div class="card"><div class="hostrow"><span class="host">{{.Snapshot.Target}}</span><span class="badge {{.Assessment.Status}}">{{upper .Assessment.Status}}</span><span class="badge risk">SECURITY RISK {{.Assessment.RiskScore}}/100</span>{{if .Baseline}}<span class="badge baseline">BASELINE</span>{{end}}</div><div class="meta">Patrol #{{.Snapshot.Sequence}} · {{.Snapshot.StartedAt.Format "2006-01-02 15:04:05"}} · {{.Snapshot.OS}}</div></div>
<div class="card"><div class="section-title">Host Health</div><div class="health-grid"><div class="health"><div class="n">{{printf "%.1f" .Assessment.Health.CPUPercent}}%</div><div class="l">CPU</div></div><div class="health"><div class="n">{{printf "%.1f" .Assessment.Health.MemoryPercent}}%</div><div class="l">Memory</div></div><div class="health"><div class="n">{{printf "%.1f" .Assessment.Health.SwapPercent}}%</div><div class="l">Swap</div></div><div class="health {{if .Assessment.Watch.ResourceHeavyProcesses}}alert{{end}}"><div class="n">{{.Assessment.Watch.ResourceHeavyProcesses}}</div><div class="l">Heavy processes</div></div></div></div>
<div class="card"><div class="section-title">Security Watch</div><div class="watch-grid"><div class="watch {{if .Assessment.Watch.NewListeners}}alert{{end}}"><div class="n">{{.Assessment.Watch.NewListeners}}</div><div class="l">New listeners</div></div><div class="watch {{if .Assessment.Watch.FailedLogins}}alert{{end}}"><div class="n">{{.Assessment.Watch.FailedLogins}}</div><div class="l">Failed logins</div></div><div class="watch {{if .Assessment.Watch.NewUsers}}alert{{end}}"><div class="n">{{.Assessment.Watch.NewUsers}}</div><div class="l">New users</div></div><div class="watch {{if .Assessment.Watch.NewServices}}alert{{end}}"><div class="n">{{.Assessment.Watch.NewServices}}</div><div class="l">New services</div></div><div class="watch {{if .Assessment.Watch.SuspiciousProcesses}}alert{{end}}"><div class="n">{{.Assessment.Watch.SuspiciousProcesses}}</div><div class="l">Suspicious processes</div></div><div class="watch {{if .Assessment.Watch.UnusualConnections}}alert{{end}}"><div class="n">{{.Assessment.Watch.UnusualConnections}}</div><div class="l">Unusual connections</div></div><div class="watch {{if .Assessment.Watch.ThreatDetections}}danger-watch{{end}}"><div class="n">{{.Assessment.Watch.ThreatDetections}}</div><div class="l">Defender threats (24h)</div></div><div class="watch {{if .Assessment.Watch.ProtectionIssues}}danger-watch{{end}}"><div class="n">{{.Assessment.Watch.ProtectionIssues}}</div><div class="l">Protection issues</div></div></div></div>
<div class="card"><div class="section-title">Assessment</div><div class="summary">{{.Assessment.Summary}}</div>{{if .Assessment.Findings}}<div class="section-title" style="margin-top:18px">Findings</div>{{range .Assessment.Findings}}<div class="finding {{.Severity}}"><div class="cat">{{.Category}} · {{upper .Severity}}</div><div>{{.Message}}</div></div>{{end}}{{end}}<div class="cols"><div><div class="section-title" style="margin-top:18px">Changes</div><ul class="compact">{{range .Assessment.Changes}}<li>{{.}}</li>{{end}}</ul></div><div><div class="section-title" style="margin-top:18px">Next</div><ul class="compact">{{range .Assessment.Next}}<li>{{.}}</li>{{end}}</ul></div></div></div>
<div class="card"><div class="section-title">Evidence</div><table><thead><tr><th>Check</th><th>Status</th><th>Summary</th><th>Raw</th></tr></thead><tbody>{{range .Snapshot.Checks}}<tr><td>{{.Name}}</td><td><span class="badge {{.Status}}">{{upper .Status}}</span></td><td>{{.Summary}}</td><td>{{if .Raw}}<details><summary>View</summary><pre>{{.Raw}}</pre></details>{{else}}—{{end}}</td></tr>{{end}}</tbody></table></div>{{else}}<div class="card empty">No patrol has completed yet.</div>{{end}}
{{if .History}}<div class="card"><div class="section-title">Recent Patrols</div>{{range .History}}<div class="history-row"><div><strong>#{{.Snapshot.Sequence}}</strong><div class="history-time">{{.Snapshot.StartedAt.Format "01-02 15:04"}}</div></div><div class="history-summary">{{.Assessment.Summary}}</div><div><span class="badge {{.Assessment.Status}}">{{upper .Assessment.Status}}</span></div><div class="history-risk">SEC RISK {{.Assessment.RiskScore}}</div></div>{{end}}</div>{{end}}
</div><script>async function runPatrol(){const b=document.querySelector('.btn');b.disabled=true;b.textContent='Patrolling…';try{const r=await fetch('/api/patrols/run',{method:'POST'});if(!r.ok)throw new Error(await r.text());location.reload()}catch(e){alert('Patrol failed: '+e.message);b.disabled=false;b.textContent='Run patrol now'}}</script></body></html>`
func (s *WebServer) String() string { return fmt.Sprintf("Outpost web server (%s)", s.addr) }
