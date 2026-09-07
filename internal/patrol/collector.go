package patrol

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

type Collector interface {
	Collect(context.Context) Snapshot
}

type LocalCollector struct{}

func NewLocalCollector() *LocalCollector { return &LocalCollector{} }

func (c *LocalCollector) Collect(ctx context.Context) Snapshot {
	host, _ := os.Hostname()
	s := Snapshot{
		Target:    host,
		Collected: time.Now(),
		Values: map[string]string{
			"os":   runtime.GOOS,
			"arch": runtime.GOARCH,
		},
		Evidence: map[string]string{},
	}

	if runtime.GOOS == "windows" {
		c.collectWindows(ctx, &s)
	} else {
		c.collectUnix(ctx, &s)
	}
	return s
}

func (c *LocalCollector) collectUnix(ctx context.Context, s *Snapshot) {
	run := func(name string, args ...string) string { return runCommand(ctx, name, args...) }
	s.Evidence["disk"] = run("df", "-P")
	s.Evidence["processes"] = run("ps", "-eo", "pid,ppid,user,%cpu,%mem,comm", "--sort=-%cpu")
	s.Evidence["network"] = firstNonEmpty(run("ss", "-tunap"), run("netstat", "-tunap"))
	s.Evidence["logins"] = run("last", "-ai")
	s.Evidence["failed_logins"] = run("lastb", "-ai")

	if b, err := os.ReadFile("/proc/meminfo"); err == nil {
		s.Evidence["memory"] = string(b)
	}
	if b, err := os.ReadFile("/proc/loadavg"); err == nil {
		s.Values["loadavg"] = strings.TrimSpace(string(b))
	}

	if _, err := exec.LookPath("apt"); err == nil {
		s.Evidence["security_updates"] = run("sh", "-c", "apt list --upgradable 2>/dev/null | head -80")
	} else if _, err := exec.LookPath("dnf"); err == nil {
		s.Evidence["security_updates"] = run("dnf", "check-update", "--security")
	}
}

func (c *LocalCollector) collectWindows(ctx context.Context, s *Snapshot) {
	ps := func(script string) string {
		return runCommand(ctx, "powershell", "-NoProfile", "-NonInteractive", "-Command", script)
	}
	s.Evidence["memory"] = ps("Get-CimInstance Win32_OperatingSystem | Select-Object TotalVisibleMemorySize,FreePhysicalMemory | Format-List")
	s.Evidence["disk"] = ps("Get-CimInstance Win32_LogicalDisk -Filter \"DriveType=3\" | Select DeviceID,Size,FreeSpace | Format-Table -AutoSize")
	s.Evidence["processes"] = ps("Get-Process | Sort-Object CPU -Descending | Select-Object -First 30 Id,ProcessName,CPU,WorkingSet64 | Format-Table -AutoSize")
	s.Evidence["network"] = ps("Get-NetTCPConnection | Select-Object -First 100 State,LocalAddress,LocalPort,RemoteAddress,RemotePort,OwningProcess | Format-Table -AutoSize")
	s.Evidence["logins"] = ps("Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624} -MaxEvents 30 -ErrorAction SilentlyContinue | Select TimeCreated,Id,Message | Format-List")
	s.Evidence["failed_logins"] = ps("Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625} -MaxEvents 30 -ErrorAction SilentlyContinue | Select TimeCreated,Id,Message | Format-List")
	s.Evidence["security_updates"] = ps("Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 20 HotFixID,InstalledOn,Description | Format-Table -AutoSize")
}

func runCommand(ctx context.Context, name string, args ...string) string {
	cmd := exec.CommandContext(ctx, name, args...)
	var out, stderr bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg == "" { msg = err.Error() }
		return fmt.Sprintf("unavailable: %s", msg)
	}
	return strings.TrimSpace(out.String())
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" && !strings.HasPrefix(v, "unavailable:") { return v }
	}
	if len(values) > 0 { return values[0] }
	return ""
}
