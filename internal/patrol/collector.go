package patrol

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

type commandCheck struct {
	Key     string
	Name    string
	Command string
	Args    []string
}

func CollectLocal(ctx context.Context) Snapshot {
	hostname, _ := os.Hostname()
	snapshot := Snapshot{
		Target:    hostname,
		OS:        runtime.GOOS,
		StartedAt: time.Now(),
	}

	checks := checksForOS(runtime.GOOS)
	for _, check := range checks {
		snapshot.Checks = append(snapshot.Checks, runCheck(ctx, check))
	}
	snapshot.FinishedAt = time.Now()
	return snapshot
}

func checksForOS(goos string) []commandCheck {
	if goos == "windows" {
		return []commandCheck{
			{Key: "disk", Name: "Disk", Command: "powershell", Args: psArgs(`Get-CimInstance Win32_LogicalDisk -Filter "DriveType=3" | Select-Object DeviceID,Size,FreeSpace | ConvertTo-Json -Compress`)},
			{Key: "processes", Name: "Processes", Command: "powershell", Args: psArgs(`Get-Process | Sort-Object CPU -Descending | Select-Object -First 20 Name,Id,CPU,WorkingSet64 | ConvertTo-Json -Compress`)},
			{Key: "network", Name: "Network", Command: "powershell", Args: psArgs(`Get-NetTCPConnection -State Established,Listen -ErrorAction SilentlyContinue | Select-Object -First 100 State,LocalAddress,LocalPort,RemoteAddress,RemotePort,OwningProcess | ConvertTo-Json -Compress`)},
			{Key: "login_history", Name: "Login history", Command: "powershell", Args: psArgs(`$start=(Get-Date).AddHours(-24); $events=@(Get-WinEvent -FilterHashtable @{LogName='Security';Id=4624;StartTime=$start} -MaxEvents 30 -ErrorAction SilentlyContinue); if($events.Count -eq 0){'[]'}else{$events | Select-Object TimeCreated,Id,ProviderName,Message | ConvertTo-Json -Compress}`)},
			{Key: "failed_logins", Name: "Failed logins", Command: "powershell", Args: psArgs(`$start=(Get-Date).AddHours(-24); $events=@(Get-WinEvent -FilterHashtable @{LogName='Security';Id=4625;StartTime=$start} -MaxEvents 30 -ErrorAction SilentlyContinue); if($events.Count -eq 0){'[]'}else{$events | Select-Object TimeCreated,Id,ProviderName,Message | ConvertTo-Json -Compress}`)},
			{Key: "security_updates", Name: "Security updates", Command: "powershell", Args: psArgs(`Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 20 HotFixID,Description,InstalledOn | ConvertTo-Json -Compress`)},
		}
	}

	return []commandCheck{
		{Key: "disk", Name: "Disk", Command: "df", Args: []string{"-P", "-h"}},
		{Key: "processes", Name: "Processes", Command: "sh", Args: []string{"-c", `ps -eo pid,user,%cpu,%mem,comm --sort=-%cpu | head -n 25`}},
		{Key: "network", Name: "Network", Command: "sh", Args: []string{"-c", `ss -tunap 2>/dev/null || netstat -tunap 2>/dev/null`}},
		{Key: "login_history", Name: "Login history", Command: "sh", Args: []string{"-c", `last -ai -n 30 2>/dev/null`}},
		{Key: "failed_logins", Name: "Failed logins", Command: "sh", Args: []string{"-c", `lastb -ai -n 30 2>/dev/null`}},
		{Key: "security_updates", Name: "Security updates", Command: "sh", Args: []string{"-c", `(command -v apt >/dev/null && apt list --upgradable 2>/dev/null | head -n 50) || (command -v dnf >/dev/null && dnf check-update --security 2>/dev/null | head -n 50) || true`}},
	}
}

func psArgs(script string) []string {
	prefix := `[Console]::OutputEncoding=[System.Text.UTF8Encoding]::new(); $OutputEncoding=[Console]::OutputEncoding; `
	return []string{"-NoProfile", "-NonInteractive", "-Command", prefix + script}
}

func runCheck(ctx context.Context, check commandCheck) CheckResult {
	cmd := exec.CommandContext(ctx, check.Command, check.Args...)
	output, err := cmd.CombinedOutput()
	text := strings.TrimSpace(string(output))

	result := CheckResult{
		Key:     check.Key,
		Name:    check.Name,
		Status:  StatusNormal,
		Summary: "collected",
		Raw:     text,
	}

	if err != nil {
		result.Status = StatusUnknown
		result.Summary = "check unavailable"
		if text == "" {
			text = err.Error()
		} else {
			text = fmt.Sprintf("%s\n%s", text, err)
		}
		result.Raw = text
	}

	hash := sha256.Sum256([]byte(result.Raw))
	result.Fingerprint = hex.EncodeToString(hash[:])
	return result
}
