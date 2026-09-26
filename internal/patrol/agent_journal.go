package patrol

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode"
)

const (
	agentJournalHeaderPrefix = "<!-- outpost-journal "
	agentJournalHeaderSuffix = " -->"
	maxAgentJournalBytes     = 768 * 1024
)

type AgentJournalWriteRequest struct {
	PatrolSequence int64    `json:"patrol_sequence,omitempty"`
	Status         string   `json:"status,omitempty"`
	Title          string   `json:"title"`
	Summary        string   `json:"summary,omitempty"`
	Tags           []string `json:"tags,omitempty"`
	Focus          []string `json:"focus,omitempty"`
	Next           []string `json:"next,omitempty"`
	Markdown       string   `json:"markdown"`
}

type AgentJournalEntry struct {
	ID             string    `json:"id"`
	CreatedAt      time.Time `json:"created_at"`
	PatrolSequence int64     `json:"patrol_sequence,omitempty"`
	Status         string    `json:"status"`
	Title          string    `json:"title"`
	Summary        string    `json:"summary,omitempty"`
	Tags           []string  `json:"tags,omitempty"`
	Focus          []string  `json:"focus,omitempty"`
	Next           []string  `json:"next,omitempty"`
	Preview        string    `json:"preview,omitempty"`
	Markdown       string    `json:"markdown,omitempty"`
	File           string    `json:"file"`
}

type agentJournalMetadata struct {
	ID             string    `json:"id"`
	CreatedAt      time.Time `json:"created_at"`
	PatrolSequence int64     `json:"patrol_sequence,omitempty"`
	Status         string    `json:"status"`
	Title          string    `json:"title"`
	Summary        string    `json:"summary,omitempty"`
	Tags           []string  `json:"tags,omitempty"`
	Focus          []string  `json:"focus,omitempty"`
	Next           []string  `json:"next,omitempty"`
}

type AgentJournalStore struct {
	dir string
	mu  sync.Mutex
}

func NewAgentJournalStore(dir string) *AgentJournalStore {
	return &AgentJournalStore{dir: dir}
}

func (s *AgentJournalStore) Dir() string { return s.dir }

func (s *AgentJournalStore) Append(req AgentJournalWriteRequest) (AgentJournalEntry, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	req.Title = strings.TrimSpace(req.Title)
	req.Summary = strings.TrimSpace(req.Summary)
	req.Markdown = strings.TrimSpace(req.Markdown)
	if req.Title == "" {
		return AgentJournalEntry{}, errors.New("journal title is required")
	}
	if req.Markdown == "" {
		return AgentJournalEntry{}, errors.New("journal markdown is required")
	}
	if len(req.Markdown) > maxAgentJournalBytes {
		return AgentJournalEntry{}, fmt.Errorf("journal markdown exceeds %d bytes", maxAgentJournalBytes)
	}

	status, err := normalizeJournalStatus(req.Status)
	if err != nil {
		return AgentJournalEntry{}, err
	}
	now := time.Now().UTC()
	id := now.Format("20060102T150405.000000000Z")
	meta := agentJournalMetadata{
		ID:             id,
		CreatedAt:      now,
		PatrolSequence: req.PatrolSequence,
		Status:         status,
		Title:          req.Title,
		Summary:        req.Summary,
		Tags:           cleanStrings(req.Tags),
		Focus:          cleanStrings(req.Focus),
		Next:           cleanStrings(req.Next),
	}
	rawMeta, err := json.Marshal(meta)
	if err != nil {
		return AgentJournalEntry{}, err
	}
	if err := os.MkdirAll(s.dir, 0o700); err != nil {
		return AgentJournalEntry{}, err
	}

	name := id + "-" + slugifyJournalTitle(req.Title) + ".md"
	path := filepath.Join(s.dir, name)
	tmp := path + ".tmp"
	payload := agentJournalHeaderPrefix + string(rawMeta) + agentJournalHeaderSuffix + "\n\n" + req.Markdown + "\n"
	if err := os.WriteFile(tmp, []byte(payload), 0o600); err != nil {
		return AgentJournalEntry{}, err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return AgentJournalEntry{}, err
	}
	return entryFromMeta(meta, name, req.Markdown, true), nil
}

func (s *AgentJournalStore) List(limit int) ([]AgentJournalEntry, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	files, err := os.ReadDir(s.dir)
	if errors.Is(err, os.ErrNotExist) {
		return []AgentJournalEntry{}, nil
	}
	if err != nil {
		return nil, err
	}

	entries := make([]AgentJournalEntry, 0, len(files))
	for _, file := range files {
		if file.IsDir() || !strings.EqualFold(filepath.Ext(file.Name()), ".md") {
			continue
		}
		entry, err := s.loadLocked(file.Name(), false)
		if err != nil {
			continue
		}
		entries = append(entries, entry)
	}
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].CreatedAt.Equal(entries[j].CreatedAt) {
			return entries[i].ID > entries[j].ID
		}
		return entries[i].CreatedAt.After(entries[j].CreatedAt)
	})
	if limit > 0 && len(entries) > limit {
		entries = entries[:limit]
	}
	return entries, nil
}

func (s *AgentJournalStore) Get(id string) (AgentJournalEntry, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	id = strings.TrimSpace(id)
	if id == "" {
		return AgentJournalEntry{}, errors.New("journal id is required")
	}
	files, err := os.ReadDir(s.dir)
	if errors.Is(err, os.ErrNotExist) {
		return AgentJournalEntry{}, os.ErrNotExist
	}
	if err != nil {
		return AgentJournalEntry{}, err
	}
	for _, file := range files {
		if file.IsDir() || !strings.EqualFold(filepath.Ext(file.Name()), ".md") {
			continue
		}
		entry, err := s.loadLocked(file.Name(), true)
		if err == nil && entry.ID == id {
			return entry, nil
		}
	}
	return AgentJournalEntry{}, os.ErrNotExist
}

func (s *AgentJournalStore) loadLocked(name string, includeMarkdown bool) (AgentJournalEntry, error) {
	path := filepath.Join(s.dir, filepath.Base(name))
	data, err := os.ReadFile(path)
	if err != nil {
		return AgentJournalEntry{}, err
	}
	info, err := os.Stat(path)
	if err != nil {
		return AgentJournalEntry{}, err
	}
	text := strings.TrimSpace(string(data))
	meta, markdown, ok := parseJournalHeader(text)
	if !ok {
		markdown = text
		meta = agentJournalMetadata{
			ID:        strings.TrimSuffix(name, filepath.Ext(name)),
			CreatedAt: info.ModTime().UTC(),
			Status:    "note",
			Title:     firstMarkdownHeading(markdown),
		}
		if meta.Title == "" {
			meta.Title = strings.TrimSuffix(name, filepath.Ext(name))
		}
	}
	return entryFromMeta(meta, name, markdown, includeMarkdown), nil
}

func parseJournalHeader(text string) (agentJournalMetadata, string, bool) {
	line, rest, found := strings.Cut(text, "\n")
	if !found {
		line = text
		rest = ""
	}
	if !strings.HasPrefix(line, agentJournalHeaderPrefix) || !strings.HasSuffix(line, agentJournalHeaderSuffix) {
		return agentJournalMetadata{}, text, false
	}
	raw := strings.TrimSuffix(strings.TrimPrefix(line, agentJournalHeaderPrefix), agentJournalHeaderSuffix)
	var meta agentJournalMetadata
	if json.Unmarshal([]byte(raw), &meta) != nil || meta.ID == "" || meta.Title == "" {
		return agentJournalMetadata{}, text, false
	}
	return meta, strings.TrimSpace(rest), true
}

func entryFromMeta(meta agentJournalMetadata, file, markdown string, includeMarkdown bool) AgentJournalEntry {
	entry := AgentJournalEntry{
		ID:             meta.ID,
		CreatedAt:      meta.CreatedAt,
		PatrolSequence: meta.PatrolSequence,
		Status:         meta.Status,
		Title:          meta.Title,
		Summary:        meta.Summary,
		Tags:           append([]string(nil), meta.Tags...),
		Focus:          append([]string(nil), meta.Focus...),
		Next:           append([]string(nil), meta.Next...),
		Preview:        markdownPreview(markdown, 360),
		File:           file,
	}
	if includeMarkdown {
		entry.Markdown = markdown
	}
	return entry
}

func normalizeJournalStatus(value string) (string, error) {
	status := strings.ToLower(strings.TrimSpace(value))
	if status == "" {
		return "note", nil
	}
	switch status {
	case "note", "normal", "warning", "danger", "unknown":
		return status, nil
	default:
		return "", fmt.Errorf("unsupported journal status %q", value)
	}
}

func cleanStrings(values []string) []string {
	out := make([]string, 0, len(values))
	seen := map[string]struct{}{}
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return out
}

func slugifyJournalTitle(value string) string {
	var b strings.Builder
	lastDash := false
	for _, r := range strings.ToLower(value) {
		switch {
		case unicode.IsLetter(r) || unicode.IsDigit(r):
			b.WriteRune(r)
			lastDash = false
		case !lastDash:
			b.WriteByte('-')
			lastDash = true
		}
	}
	slug := strings.Trim(b.String(), "-")
	if slug == "" {
		return "journal"
	}
	runes := []rune(slug)
	if len(runes) > 48 {
		slug = string(runes[:48])
	}
	return slug
}

func firstMarkdownHeading(markdown string) string {
	for _, line := range strings.Split(markdown, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "#") {
			title := strings.TrimSpace(strings.TrimLeft(line, "#"))
			if title != "" {
				return title
			}
		}
	}
	return ""
}

func markdownPreview(markdown string, limit int) string {
	text := strings.TrimSpace(markdown)
	if limit <= 0 {
		return ""
	}
	runes := []rune(text)
	if len(runes) <= limit {
		return text
	}
	return string(runes[:limit]) + "…"
}
