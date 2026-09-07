package patrol

import (
	"path/filepath"
	"testing"
)

func TestJournalNormalizesLegacySequences(t *testing.T) {
	path := filepath.Join(t.TempDir(), "journal.jsonl")
	j := NewJournal(path)
	for _, seq := range []int64{1, 2, 1, 1, 6} {
		if err := j.Append(PatrolReport{Snapshot: Snapshot{Sequence: seq, Target: "host"}}); err != nil {
			t.Fatalf("append: %v", err)
		}
	}
	if err := j.NormalizeSequences(); err != nil {
		t.Fatalf("normalize: %v", err)
	}
	recent, err := j.Recent(10)
	if err != nil { t.Fatalf("recent: %v", err) }
	if len(recent) != 5 { t.Fatalf("expected 5 reports, got %d", len(recent)) }
	for i, report := range recent {
		expected := int64(5 - i)
		if report.Snapshot.Sequence != expected {
			t.Fatalf("report %d: expected sequence %d, got %d", i, expected, report.Snapshot.Sequence)
		}
	}
}
