package patrol

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"net/http"
	"strings"
	"time"
)

type WebServer struct {
	addr   string
	runner *Runner
	tmpl   *template.Template
}

func NewWebServer(addr string, runner *Runner) *WebServer {
	return &WebServer{
		addr:   addr,
		runner: runner,
		tmpl:   template.Must(template.New("index").Funcs(template.FuncMap{"upper": strings.ToUpper}).Parse(indexHTML)),
	}
}

func (s *WebServer) Run(ctx context.Context) error {
	server := &http.Server{
		Addr:              s.addr,
		Handler:           s.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
	}

	errCh := make(chan error, 1)
	go func() {
		errCh <- server.ListenAndServe()
	}()

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
	mux.HandleFunc("POST /api/patrols/run", s.handleRun)
	return mux
}

func (s *WebServer) handleIndex(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := s.tmpl.Execute(w, s.runner.Latest()); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func (s *WebServer) handleStatus(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"latest": s.runner.Latest(), "time": time.Now()})
}

func (s *WebServer) handlePatrols(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"latest": s.runner.Latest()})
}

func (s *WebServer) handleRun(w http.ResponseWriter, r *http.Request) {
	report, err := s.runner.RunOnce(r.Context())
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, report)
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
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Outpost</title>
<style>
:root{font-family:Inter,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;color:#20242b;background:#f4f6f8}body{margin:0}.wrap{max-width:980px;margin:0 auto;padding:32px 20px 64px}.top{display:flex;justify-content:space-between;gap:20px;align-items:center;margin-bottom:24px}h1{margin:0;font-size:32px}.subtitle{color:#69717d;margin-top:4px}.btn{border:0;border-radius:8px;padding:10px 16px;font-weight:600;cursor:pointer;background:#20242b;color:white}.card{background:white;border:1px solid #e2e6ea;border-radius:12px;padding:20px;margin-bottom:16px;box-shadow:0 1px 2px rgba(0,0,0,.03)}.hostrow{display:flex;align-items:center;gap:10px;flex-wrap:wrap}.host{font-size:22px;font-weight:700}.badge{display:inline-block;padding:4px 9px;border-radius:999px;font-size:12px;font-weight:700}.normal{background:#e9f7ef;color:#187443}.warning{background:#fff4d6;color:#8a5a00}.danger{background:#fde8e8;color:#a32323}.unknown{background:#eceff3;color:#5d6673}.baseline{background:#eaf1ff;color:#2454a6}.meta{color:#69717d;font-size:13px;margin-top:6px}table{width:100%;border-collapse:collapse;margin-top:14px}th,td{text-align:left;padding:10px 8px;border-bottom:1px solid #edf0f2;vertical-align:top}th{font-size:12px;color:#69717d;text-transform:uppercase;letter-spacing:.04em}.section-title{font-size:13px;color:#69717d;text-transform:uppercase;letter-spacing:.05em;margin:18px 0 7px}.compact{margin:0;padding-left:18px}.compact li{margin:5px 0}.empty{text-align:center;color:#69717d;padding:40px 0}details{margin-top:4px}pre{white-space:pre-wrap;word-break:break-word;font-size:12px;background:#f7f8fa;padding:10px;border-radius:8px;max-height:280px;overflow:auto}
</style>
</head>
<body><div class="wrap">
<div class="top"><div><h1>Outpost</h1><div class="subtitle">Server patrol journal</div></div><button class="btn" onclick="runPatrol()">Run patrol now</button></div>
{{if .}}
<div class="card">
  <div class="hostrow">
    <span class="host">{{.Snapshot.Target}}</span>
    <span class="badge {{.Assessment.Status}}">{{upper .Assessment.Status}}</span>
    {{if .Baseline}}<span class="badge baseline">BASELINE</span>{{end}}
  </div>
  <div class="meta">Patrol #{{.Snapshot.Sequence}} · {{.Snapshot.StartedAt.Format "2006-01-02 15:04:05"}} · {{.Snapshot.OS}}</div>
  <table><thead><tr><th>Check</th><th>Status</th><th>Summary</th><th>Evidence</th></tr></thead><tbody>
  {{range .Snapshot.Checks}}<tr><td>{{.Name}}</td><td><span class="badge {{.Status}}">{{upper .Status}}</span></td><td>{{.Summary}}</td><td>{{if .Raw}}<details><summary>View</summary><pre>{{.Raw}}</pre></details>{{else}}—{{end}}</td></tr>{{end}}
  </tbody></table>
</div>
<div class="card">
  <div class="section-title">Assessment</div><div>{{.Assessment.Summary}}</div>
  <div class="section-title">Changes</div><ul class="compact">{{range .Assessment.Changes}}<li>{{.}}</li>{{end}}</ul>
  <div class="section-title">Next</div><ul class="compact">{{range .Assessment.Next}}<li>{{.}}</li>{{end}}</ul>
</div>
{{else}}<div class="card empty">No patrol has completed yet.</div>{{end}}
</div>
<script>
async function runPatrol(){
  const b=document.querySelector('.btn'); b.disabled=true; b.textContent='Patrolling…';
  try{const r=await fetch('/api/patrols/run',{method:'POST'}); if(!r.ok) throw new Error(await r.text()); location.reload();}
  catch(e){alert('Patrol failed: '+e.message); b.disabled=false; b.textContent='Run patrol now';}
}
</script>
</body></html>`

func (s *WebServer) String() string { return fmt.Sprintf("Outpost web server (%s)", s.addr) }
