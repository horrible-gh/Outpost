package patrol

import (
	"context"
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"strconv"
	"time"
)

type WebServer struct {
	addr   string
	runner *Runner
}

func NewWebServer(addr string, runner *Runner) *WebServer {
	if addr == "" { addr = "127.0.0.1:8787" }
	return &WebServer{addr: addr, runner: runner}
}

func (s *WebServer) Run(ctx context.Context) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handleIndex)
	mux.HandleFunc("/api/status", s.handleStatus)
	mux.HandleFunc("/api/patrols", s.handlePatrols)
	mux.HandleFunc("/api/patrols/run", s.handleRun)

	httpServer := &http.Server{Addr: s.addr, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	errCh := make(chan error, 1)
	go func() { errCh <- httpServer.ListenAndServe() }()
	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return httpServer.Shutdown(shutdownCtx)
	case err := <-errCh:
		if err == http.ErrServerClosed { return nil }
		return err
	}
}

func (s *WebServer) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" { http.NotFound(w, r); return }
	reports, _ := s.runner.Recent(20)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = indexTemplate.Execute(w, map[string]any{"Reports": reports})
}

func (s *WebServer) handleStatus(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, s.runner.Latest())
}

func (s *WebServer) handlePatrols(w http.ResponseWriter, r *http.Request) {
	limit := 20
	if v, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil && v > 0 && v <= 200 { limit = v }
	reports, err := s.runner.Recent(limit)
	if err != nil { http.Error(w, err.Error(), http.StatusInternalServerError); return }
	writeJSON(w, reports)
}

func (s *WebServer) handleRun(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost { http.Error(w, "POST required", http.StatusMethodNotAllowed); return }
	report, err := s.runner.RunOnce(r.Context())
	if err != nil { http.Error(w, err.Error(), http.StatusInternalServerError); return }
	writeJSON(w, report)
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(v)
}

var indexTemplate = template.Must(template.New("index").Funcs(template.FuncMap{
	"when": func(t time.Time) string { return t.Format("2006-01-02 15:04:05") },
	"upper": func(v Severity) string { return fmt.Sprintf("%s", v) },
}).Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Outpost</title><style>
body{font-family:system-ui,sans-serif;background:#111827;color:#e5e7eb;margin:0}.wrap{max-width:1050px;margin:auto;padding:32px}.head{display:flex;justify-content:space-between;align-items:center}.muted{color:#9ca3af}.card{background:#1f2937;border:1px solid #374151;border-radius:12px;padding:18px;margin-top:16px}.row{display:flex;gap:14px;align-items:center;flex-wrap:wrap}.status{font-weight:700;text-transform:uppercase}.normal{color:#86efac}.warning{color:#fde047}.danger{color:#fca5a5}.unknown{color:#c4b5fd}table{width:100%;border-collapse:collapse;margin-top:12px}th,td{text-align:left;padding:8px;border-bottom:1px solid #374151}button{background:#e5e7eb;color:#111827;border:0;border-radius:8px;padding:9px 14px;font-weight:700;cursor:pointer}ul{margin:8px 0}
</style></head><body><div class="wrap"><div class="head"><div><h1>Outpost</h1><div class="muted">Server patrol journal</div></div><button onclick="runPatrol()">Run patrol now</button></div>
{{if .Reports}}{{range .Reports}}<section class="card"><div class="row"><strong>{{.Target}}</strong><span class="status {{.Status}}">{{upper .Status}}</span><span class="muted">{{when .FinishedAt}}</span></div><table><tr><th>Check</th><th>Status</th><th>Summary</th></tr>{{range .Checks}}<tr><td>{{.Label}}</td><td class="status {{.Severity}}">{{upper .Severity}}</td><td>{{.Summary}}</td></tr>{{end}}</table><div class="row"><div><strong>Assessment</strong><ul>{{range .Assessment}}<li>{{.}}</li>{{end}}</ul></div><div><strong>Next</strong><ul>{{range .Next}}<li>{{.}}</li>{{end}}</ul></div></div></section>{{end}}{{else}}<div class="card muted">No patrol reports yet.</div>{{end}}</div><script>
async function runPatrol(){const b=document.querySelector('button');b.disabled=true;b.textContent='Patrolling...';try{const r=await fetch('/api/patrols/run',{method:'POST'});if(!r.ok)throw new Error(await r.text());location.reload()}catch(e){alert(e.message);b.disabled=false;b.textContent='Run patrol now'}}
</script></body></html>`))
