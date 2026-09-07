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

func (j *Journal) Append(report Report) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	f, err := os.OpenFile(j.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil { return err }
	defer f.Close()
	return json.NewEncoder(f).Encode(report)
}

func (j *Journal) Recent(limit int) ([]Report, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	f, err := os.Open(j.path)
	if errors.Is(err, os.ErrNotExist) { return []Report{}, nil }
	if err != nil { return nil, err }
	defer f.Close()

	var all []Report
	s := bufio.NewScanner(f)
	buf := make([]byte, 64*1024)
	s.Buffer(buf, 4*1024*1024)
	for s.Scan() {
		var r Report
		if json.Unmarshal(s.Bytes(), &r) == nil { all = append(all, r) }
	}
	if err := s.Err(); err != nil { return nil, err }
	if limit <= 0 || len(all) <= limit { reverse(all); return all, nil }
	all = all[len(all)-limit:]
	reverse(all)
	return all, nil
}

func reverse(v []Report) {
	for i, k := 0, len(v)-1; i < k; i, k = i+1, k-1 { v[i], v[k] = v[k], v[i] }
}
