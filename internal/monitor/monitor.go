package monitor

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

type Status string

const (
	StatusUp      Status = "up"
	StatusWarning Status = "warning"
	StatusDown    Status = "down"
	StatusUnknown Status = "unknown"
)

type Target struct {
	ID             string `json:"id"`
	Name           string `json:"name"`
	URL            string `json:"url"`
	ExpectedStatus int    `json:"expected_status"`
	MaxLatencyMS   int64  `json:"max_latency_ms"`
	BodyContains   string `json:"body_contains,omitempty"`
	Enabled        bool   `json:"enabled"`
}

type Result struct {
	TargetID       string    `json:"target_id"`
	Name           string    `json:"name"`
	URL            string    `json:"url"`
	Status         Status    `json:"status"`
	CheckedAt      time.Time `json:"checked_at"`
	LatencyMS      int64     `json:"latency_ms"`
	HTTPStatus     int       `json:"http_status"`
	DNSAddresses   []string  `json:"dns_addresses,omitempty"`
	TCPReachable   bool      `json:"tcp_reachable"`
	TLSExpiresAt   time.Time `json:"tls_expires_at,omitempty"`
	TLSDaysLeft    int       `json:"tls_days_left,omitempty"`
	ContentMatched bool      `json:"content_matched"`
	Summary        string    `json:"summary"`
	Error          string    `json:"error,omitempty"`
}

type RunnerConfig struct {
	Interval   time.Duration
	Timeout    time.Duration
	ConfigPath string
	RunOnBoot  bool
}

type Runner struct {
	cfg     RunnerConfig
	mu      sync.RWMutex
	targets []Target
	latest  map[string]Result
	history []Result
}

func NewRunner(cfg RunnerConfig) *Runner {
	if cfg.Interval <= 0 {
		cfg.Interval = 5 * time.Minute
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 10 * time.Second
	}
	if cfg.ConfigPath == "" {
		cfg.ConfigPath = "outpost-services.json"
	}
	r := &Runner{cfg: cfg, latest: make(map[string]Result)}
	if err := r.load(); err != nil && !errors.Is(err, os.ErrNotExist) {
		slog.Warn("service monitor configuration load failed", "error", err)
	}
	return r
}

func (r *Runner) Run(ctx context.Context) error {
	if r.cfg.RunOnBoot {
		if _, err := r.RunOnce(ctx); err != nil {
			slog.Warn("initial service monitor check failed", "error", err)
		}
	}
	ticker := time.NewTicker(r.cfg.Interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			if _, err := r.RunOnce(ctx); err != nil {
				slog.Warn("scheduled service monitor check failed", "error", err)
			}
		}
	}
}

func (r *Runner) RunOnce(parent context.Context) ([]Result, error) {
	targets := r.Targets()
	results := make([]Result, 0, len(targets))
	for _, target := range targets {
		if !target.Enabled {
			continue
		}
		ctx, cancel := context.WithTimeout(parent, r.cfg.Timeout)
		result := checkTarget(ctx, target)
		cancel()
		results = append(results, result)
		r.record(result)
	}
	return results, nil
}

func (r *Runner) RunTarget(parent context.Context, id string) (Result, error) {
	target, ok := r.Target(id)
	if !ok {
		return Result{}, fmt.Errorf("service target %q not found", id)
	}
	ctx, cancel := context.WithTimeout(parent, r.cfg.Timeout)
	defer cancel()
	result := checkTarget(ctx, target)
	r.record(result)
	return result, nil
}

func (r *Runner) Targets() []Target {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := append([]Target(nil), r.targets...)
	sort.Slice(out, func(i, j int) bool { return strings.ToLower(out[i].Name) < strings.ToLower(out[j].Name) })
	return out
}

func (r *Runner) Target(id string) (Target, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, target := range r.targets {
		if target.ID == id {
			return target, true
		}
	}
	return Target{}, false
}

func (r *Runner) Latest() []Result {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]Result, 0, len(r.latest))
	for _, result := range r.latest {
		out = append(out, result)
	}
	sort.Slice(out, func(i, j int) bool { return strings.ToLower(out[i].Name) < strings.ToLower(out[j].Name) })
	return out
}

func (r *Runner) History(limit int) []Result {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if limit <= 0 || limit > len(r.history) {
		limit = len(r.history)
	}
	out := make([]Result, limit)
	copy(out, r.history[len(r.history)-limit:])
	return out
}

func (r *Runner) AddTarget(target Target) (Target, error) {
	target.Name = strings.TrimSpace(target.Name)
	target.URL = strings.TrimSpace(target.URL)
	if target.Name == "" {
		return Target{}, errors.New("service name is required")
	}
	parsed, err := url.Parse(target.URL)
	if err != nil || parsed.Hostname() == "" || (parsed.Scheme != "http" && parsed.Scheme != "https") {
		return Target{}, errors.New("service URL must be a valid http or https URL")
	}
	if target.ExpectedStatus == 0 {
		target.ExpectedStatus = http.StatusOK
	}
	if target.MaxLatencyMS <= 0 {
		target.MaxLatencyMS = 1000
	}
	if target.ID == "" {
		target.ID = newID()
	}
	// New targets are enabled unless the caller explicitly updates the persisted file later.
	target.Enabled = true

	r.mu.Lock()
	for _, existing := range r.targets {
		if existing.ID == target.ID {
			r.mu.Unlock()
			return Target{}, fmt.Errorf("service target %q already exists", target.ID)
		}
	}
	r.targets = append(r.targets, target)
	err = r.saveLocked()
	r.mu.Unlock()
	if err != nil {
		return Target{}, err
	}
	return target, nil
}

func (r *Runner) RemoveTarget(id string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	for i, target := range r.targets {
		if target.ID != id {
			continue
		}
		r.targets = append(r.targets[:i], r.targets[i+1:]...)
		delete(r.latest, id)
		return r.saveLocked()
	}
	return fmt.Errorf("service target %q not found", id)
}

func (r *Runner) ConfigPath() string { return r.cfg.ConfigPath }
func (r *Runner) Interval() time.Duration { return r.cfg.Interval }

func (r *Runner) record(result Result) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.latest[result.TargetID] = result
	r.history = append(r.history, result)
	if len(r.history) > 500 {
		r.history = append([]Result(nil), r.history[len(r.history)-500:]...)
	}
}

func (r *Runner) load() error {
	data, err := os.ReadFile(r.cfg.ConfigPath)
	if err != nil {
		return err
	}
	var targets []Target
	if err := json.Unmarshal(data, &targets); err != nil {
		return err
	}
	for i := range targets {
		if targets[i].ID == "" {
			targets[i].ID = newID()
		}
		if targets[i].ExpectedStatus == 0 {
			targets[i].ExpectedStatus = http.StatusOK
		}
		if targets[i].MaxLatencyMS <= 0 {
			targets[i].MaxLatencyMS = 1000
		}
	}
	r.targets = targets
	return nil
}

func (r *Runner) saveLocked() error {
	data, err := json.MarshalIndent(r.targets, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(r.cfg.ConfigPath, append(data, '\n'), 0o600)
}

func checkTarget(ctx context.Context, target Target) Result {
	result := Result{
		TargetID:       target.ID,
		Name:           target.Name,
		URL:            target.URL,
		Status:         StatusUnknown,
		CheckedAt:      time.Now(),
		ContentMatched: target.BodyContains == "",
	}

	parsed, err := url.Parse(target.URL)
	if err != nil {
		return fail(result, "invalid URL", err)
	}
	host := parsed.Hostname()
	addresses, err := net.DefaultResolver.LookupHost(ctx, host)
	if err != nil {
		return fail(result, "DNS lookup failed", err)
	}
	result.DNSAddresses = addresses

	port := parsed.Port()
	if port == "" {
		if parsed.Scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}
	address := net.JoinHostPort(host, port)
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	conn, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		return fail(result, "TCP connection failed", err)
	}
	result.TCPReachable = true
	_ = conn.Close()

	if parsed.Scheme == "https" {
		tlsDialer := &tls.Dialer{NetDialer: dialer, Config: &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12}}
		tlsConn, err := tlsDialer.DialContext(ctx, "tcp", address)
		if err != nil {
			return fail(result, "TLS handshake failed", err)
		}
		state := tlsConn.(*tls.Conn).ConnectionState()
		if len(state.PeerCertificates) > 0 {
			result.TLSExpiresAt = state.PeerCertificates[0].NotAfter
			result.TLSDaysLeft = int(time.Until(result.TLSExpiresAt).Hours() / 24)
		}
		_ = tlsConn.Close()
	}

	request, err := http.NewRequestWithContext(ctx, http.MethodGet, target.URL, nil)
	if err != nil {
		return fail(result, "HTTP request creation failed", err)
	}
	client := &http.Client{Timeout: 10 * time.Second}
	started := time.Now()
	response, err := client.Do(request)
	result.LatencyMS = time.Since(started).Milliseconds()
	if err != nil {
		return fail(result, "HTTP request failed", err)
	}
	defer response.Body.Close()
	result.HTTPStatus = response.StatusCode
	body, err := io.ReadAll(io.LimitReader(response.Body, 64*1024))
	if err != nil {
		return fail(result, "HTTP response read failed", err)
	}
	if target.BodyContains != "" {
		result.ContentMatched = strings.Contains(string(body), target.BodyContains)
	}

	if response.StatusCode != target.ExpectedStatus {
		result.Status = StatusDown
		result.Summary = fmt.Sprintf("HTTP %d; expected %d", response.StatusCode, target.ExpectedStatus)
		return result
	}
	if !result.ContentMatched {
		result.Status = StatusDown
		result.Summary = "expected response content was not found"
		return result
	}
	if !result.TLSExpiresAt.IsZero() && result.TLSDaysLeft < 0 {
		result.Status = StatusDown
		result.Summary = "TLS certificate is expired"
		return result
	}
	if (!result.TLSExpiresAt.IsZero() && result.TLSDaysLeft < 14) || result.LatencyMS > target.MaxLatencyMS {
		result.Status = StatusWarning
		if !result.TLSExpiresAt.IsZero() && result.TLSDaysLeft < 14 {
			result.Summary = fmt.Sprintf("service is reachable; TLS certificate expires in %d days", result.TLSDaysLeft)
		} else {
			result.Summary = fmt.Sprintf("service is reachable but latency is %d ms", result.LatencyMS)
		}
		return result
	}
	result.Status = StatusUp
	result.Summary = fmt.Sprintf("HTTP %d in %d ms", result.HTTPStatus, result.LatencyMS)
	return result
}

func fail(result Result, summary string, err error) Result {
	result.Status = StatusDown
	result.Summary = summary
	if err != nil {
		result.Error = err.Error()
	}
	return result
}

func newID() string {
	var data [8]byte
	if _, err := rand.Read(data[:]); err != nil {
		return fmt.Sprintf("svc-%d", time.Now().UnixNano())
	}
	return "svc-" + hex.EncodeToString(data[:])
}
