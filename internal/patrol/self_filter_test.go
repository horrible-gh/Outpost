package patrol

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestRemoveProcessPIDWindows(t *testing.T) {
	raw := `[{"Name":"outpost.exe","ProcessId":123,"ExecutablePath":"C:\\Users\\dev\\AppData\\Local\\Temp\\go-build\\outpost.exe"},{"Name":"other.exe","ProcessId":456,"ExecutablePath":"C:\\Apps\\other.exe"}]`
	got, changed := removeProcessPID(raw, 123, "windows")
	if !changed { t.Fatal("expected self process to be removed") }
	if strings.Contains(got, "outpost.exe") { t.Fatalf("self process still present: %s", got) }
	var rows []map[string]any
	if err := json.Unmarshal([]byte(got), &rows); err != nil { t.Fatal(err) }
	if len(rows) != 1 || rows[0]["Name"] != "other.exe" { t.Fatalf("unexpected rows: %#v", rows) }
}

func TestRemoveProcessPIDLinux(t *testing.T) {
	raw := "PID USER %CPU %MEM COMMAND\n123 user 1.0 0.1 outpost\n456 user 2.0 0.2 other"
	got, changed := removeProcessPID(raw, 123, "linux")
	if !changed { t.Fatal("expected self process to be removed") }
	if strings.Contains(got, "123 user") { t.Fatalf("self process still present: %s", got) }
	if !strings.Contains(got, "456 user") { t.Fatalf("other process missing: %s", got) }
}
