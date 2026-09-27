package patrol

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAgentJournalStoreRoundTrip(t *testing.T) {
	dir := t.TempDir()
	store := NewAgentJournalStore(dir)
	entry, err := store.Append(AgentJournalWriteRequest{
		PatrolSequence: 12,
		Status:         "warning",
		Title:          "Docker storage follow-up",
		Summary:        "Container logs are growing.",
		Tags:           []string{"docker", "storage", "docker"},
		Focus:          []string{"container logs"},
		Next:           []string{"recheck log growth tomorrow"},
		Markdown:       "# Patrol note\n\nInvestigated Docker storage read-only.",
	})
	if err != nil {
		t.Fatalf("append: %v", err)
	}
	if entry.ID == "" || entry.File == "" {
		t.Fatalf("expected id and file, got %#v", entry)
	}
	if entry.PatrolSequence != 12 || entry.Status != "warning" || entry.Kind != "journal" || entry.Author != "agent" {
		t.Fatalf("unexpected entry metadata: %#v", entry)
	}
	if !strings.Contains(entry.HTML, "<h1>Patrol note</h1>") {
		t.Fatalf("expected rendered HTML, got %q", entry.HTML)
	}
	if len(entry.Tags) != 2 {
		t.Fatalf("expected duplicate tags removed, got %#v", entry.Tags)
	}

	list, err := store.List(10)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(list) != 1 {
		t.Fatalf("expected one journal, got %d", len(list))
	}
	if list[0].Markdown != "" {
		t.Fatalf("list should not include full markdown")
	}
	if !strings.Contains(list[0].Preview, "Investigated Docker") {
		t.Fatalf("expected preview, got %q", list[0].Preview)
	}

	full, err := store.Get(entry.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if !strings.Contains(full.Markdown, "Investigated Docker storage") {
		t.Fatalf("unexpected markdown: %q", full.Markdown)
	}
}

func TestAgentJournalStoreListsStandaloneMarkdown(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "manual-note.md")
	if err := os.WriteFile(path, []byte("# Manual patrol\n\nA Codex-created note."), 0o600); err != nil {
		t.Fatalf("write manual markdown: %v", err)
	}
	store := NewAgentJournalStore(dir)
	list, err := store.List(10)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(list) != 1 {
		t.Fatalf("expected one journal, got %d", len(list))
	}
	if list[0].ID != "manual-note" || list[0].Title != "Manual patrol" || list[0].Status != "note" {
		t.Fatalf("unexpected standalone markdown metadata: %#v", list[0])
	}
}


func TestAgentJournalDirectiveIsSeparatedFromAgentJournal(t *testing.T) {
	store := NewAgentJournalStore(t.TempDir())
	directive, err := store.Append(AgentJournalWriteRequest{
		Kind: "directive",
		Title: "Inspect Docker logs",
		Markdown: "Check **log rotation** and anything suspicious around it.",
	})
	if err != nil {
		t.Fatalf("append directive: %v", err)
	}
	if directive.Kind != "directive" || directive.Author != "user" {
		t.Fatalf("unexpected directive defaults: %#v", directive)
	}
	if !strings.Contains(directive.HTML, "<strong>log rotation</strong>") {
		t.Fatalf("expected rendered directive markdown, got %q", directive.HTML)
	}

	if _, err := store.Append(AgentJournalWriteRequest{
		Title: "Agent result",
		Markdown: "Nothing unusual.",
	}); err != nil {
		t.Fatalf("append journal: %v", err)
	}

	directives, err := store.ListKind("directive", 10)
	if err != nil {
		t.Fatalf("list directives: %v", err)
	}
	if len(directives) != 1 || directives[0].ID != directive.ID {
		t.Fatalf("unexpected directives: %#v", directives)
	}
	journals, err := store.ListKind("journal", 10)
	if err != nil {
		t.Fatalf("list journals: %v", err)
	}
	if len(journals) != 1 || journals[0].Kind != "journal" {
		t.Fatalf("unexpected journals: %#v", journals)
	}
}

func TestAgentJournalRejectsUnsupportedKind(t *testing.T) {
	store := NewAgentJournalStore(t.TempDir())
	_, err := store.Append(AgentJournalWriteRequest{
		Kind: "mission-control",
		Title: "bad",
		Markdown: "bad",
	})
	if err == nil || !strings.Contains(err.Error(), "unsupported journal kind") {
		t.Fatalf("expected unsupported kind error, got %v", err)
	}
}
