package patrol

import (
	"bufio"
	"encoding/json"
	"errors"
	"os"
	"sync"
)

type Journal struct {
	path string
	mu   sync.Mutex
}

func NewJournal(path string) *Journal { return &Journal{path: path} }

func (j *Journal) Append(report PatrolReport) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	f, err := os.OpenFile(j.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil { return err }
	defer f.Close()
	return json.NewEncoder(f).Encode(report)
}

func (j *Journal) Recent(limit int) ([]PatrolReport, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	all, err := j.readAllLocked()
	if err != nil { return nil, err }
	if limit <= 0 || len(all) <= limit {
		reverse(all)
		return all, nil
	}
	all = all[len(all)-limit:]
	reverse(all)
	return all, nil
}

// NormalizeSequences repairs journals created by early development builds where
// sequence numbers could restart after process restarts. It preserves all valid
// reports and only rewrites the journal when the sequence is not strictly 1..N.
func (j *Journal) NormalizeSequences() error {
	j.mu.Lock()
	defer j.mu.Unlock()

	all, err := j.readAllLocked()
	if err != nil { return err }
	if len(all) == 0 { return nil }

	needsRewrite := false
	for i := range all {
		expected := int64(i + 1)
		if all[i].Snapshot.Sequence != expected {
			all[i].Snapshot.Sequence = expected
			needsRewrite = true
		}
	}
	if !needsRewrite { return nil }

	tmp := j.path + ".tmp"
	backup := j.path + ".bak"
	_ = os.Remove(tmp)
	_ = os.Remove(backup)

	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil { return err }
	enc := json.NewEncoder(f)
	for _, report := range all {
		if err := enc.Encode(report); err != nil {
			_ = f.Close()
			_ = os.Remove(tmp)
			return err
		}
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return err
	}

	if err := os.Rename(j.path, backup); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, j.path); err != nil {
		_ = os.Rename(backup, j.path)
		_ = os.Remove(tmp)
		return err
	}
	_ = os.Remove(backup)
	return nil
}

func (j *Journal) readAllLocked() ([]PatrolReport, error) {
	f, err := os.Open(j.path)
	if errors.Is(err, os.ErrNotExist) { return []PatrolReport{}, nil }
	if err != nil { return nil, err }
	defer f.Close()

	var all []PatrolReport
	s := bufio.NewScanner(f)
	buf := make([]byte, 64*1024)
	s.Buffer(buf, 4*1024*1024)
	for s.Scan() {
		var r PatrolReport
		if json.Unmarshal(s.Bytes(), &r) == nil { all = append(all, r) }
	}
	if err := s.Err(); err != nil { return nil, err }
	return all, nil
}

func reverse(v []PatrolReport) {
	for i, k := 0, len(v)-1; i < k; i, k = i+1, k-1 {
		v[i], v[k] = v[k], v[i]
	}
}
