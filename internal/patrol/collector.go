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
	snapshot := Snapshot{Target: hostname, OS: runtime.GOOS, StartedAt: time.Now()}
	for _, check := range checksForOS(runtime.GOOS) {
		snapshot.Checks = append(snapshot.Checks, runCheck(ctx, check))
	}
	snapshot.FinishedAt = time.Now()
	return snapshot
}

func checksForOS(goos string) []commandCheck {
	if goos == "windows" {
		prefix := `$OutputEncoding=[Console]::OutputEncoding=[Text.UTF8Encoding]::new(); `
		return []commandCheck{
			{Key: "system_health", Name: "System health", Command: "powershell", Args: []string{"-NoProfile", "-NonInteractive", "-Command", prefix + `$os=Get-CimInstance Win32_OperatingSystem; $cpu=[double]((Get-CimInstance Win32_Processor | Measure-Object LoadPercentage -Average).Average); $mem=[double](100*(($os.TotalVisibleMemorySize-$os.FreePhysicalMemory)/$os.TotalVisibleMemorySize)); $pf=@(Get-CimInstance Win32_PageFileUsage); $swap=0.0; if($pf.Count -gt 0){$allocated=($pf|Measure-Object AllocatedBaseSize -Sum).Sum; $used=($pf|Measure-Object CurrentUsage -Sum).Sum; if($allocated -gt 0){$swap=[double](100*$used/$allocated)}}; [pscustomobject]@{CPUPercent=[math]::Round($cpu,1);MemoryPercent=[math]::Round($mem,1);SwapPercent=[math]::Round($swap,1)} | ConvertTo-Json -Compress`}},
			{Key: "disk", Name: "Disk", Command: "powershell", Args: []string{"-NoProfile", "-NonInteractive", "-Command", prefix + `Get-CimInstance Win32_LogicalDisk -Filter "DriveType=3" | Select-Object DeviceID,Size,FreeSpace | ConvertTo-Json -Compress`}},
			{Key: "processes", Name: "Processes", Command: "powershell", Args: []string{"-NoProfile", "-NonInteractive", "-Command", prefix + `Get-CimInstance Win32_Process | Select-Object Name,ProcessId,ExecutablePath,CommandLine,WorkingSetSize | ConvertTo-Json -Compress`}},
			{Key: "process_pressure", Name: "Process pressure", Command: "powershell", Args: []string{"-NoProfile", "-NonInteractive", "-Command", prefix + `$cores=[double](Get-CimInstance Win32_ComputerSystem).NumberOfLogicalProcessors; $mem=[double](Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory; Get-CimInstance Win32_PerfFormattedData_PerfProc_Process | Where-Object {$_.IDProcess -gt 0 -and $_.Name -notin @('_Total','Idle')} | ForEach-Object {[pscustomobject]@{Name=$_.Name;ProcessId=$_.IDProcess;CPUPercent=[math]::Round(([double]$_.PercentProcessorTime/[math]::Max($cores,1)),1);MemoryPercent=[math]::Round((100*[double]$_.WorkingSetPrivate/[math]::Max($mem,1)),1)}} | Sort-Object CPUPercent -Descending | Select-Object -First 30 | ConvertTo-Json -Compress`}},
			{Key: "network", Name: "Network", Command: "powershell", Args: []string{"-NoProfile", "-NonInteractive", "-Command", prefix + `Get-NetTCPConnection -State Established,Listen -ErrorAction SilentlyContinue | Select-Object State,LocalAddress,LocalPort,RemoteAddress,RemotePort,OwningProcess | ConvertTo-Json -Compress`}},
			{Key: "login_history", Name: "Login history", Command: "powershell", Args: []string{"-NoProfile", "-NonInteractive", "-Command", prefix + `$start=(Get-Date).AddHours(-24); $e=@(Get-WinEvent -FilterHashtable @{LogName='Security';Id=4624;StartTime=$start} -MaxEvents 30 -ErrorAction SilentlyContinue); $e | Select-Object TimeCreated,Id,ProviderName,Message | ConvertTo-Json -Compress; if($e.Count -eq 0){'[]'}`}},
			{Key: "failed_logins", Name: "Failed logins", Command: "powershell", Args: []string{"-NoProfile", "-NonInteractive", "-Command", prefix + `$start=(Get-Date).AddHours(-24); $e=@(Get-WinEvent -FilterHashtable @{LogName='Security';Id=4625;StartTime=$start} -MaxEvents 30 -ErrorAction SilentlyContinue); $e | Select-Object TimeCreated,Id,ProviderName,Message | ConvertTo-Json -Compress; if($e.Count -eq 0){'[]'}`}},
			{Key: "users", Name: "Local users", Command: "powershell", Args: []string{"-NoProfile", "-NonInteractive", "-Command", prefix + `Get-LocalUser | Select-Object Name,Enabled,SID,LastLogon | ConvertTo-Json -Compress`}},
			{Key: "services", Name: "Auto-start services", Command: "powershell", Args: []string{"-NoProfile", "-NonInteractive", "-Command", prefix + `Get-CimInstance Win32_Service | Where-Object {$_.StartMode -eq 'Auto'} | Select-Object Name,State,StartMode,StartName,PathName | ConvertTo-Json -Compress`}},
			{Key: "defender_status", Name: "Defender status", Command: "powershell", Args: []string{"-NoProfile", "-NonInteractive", "-Command", prefix + `Get-MpComputerStatus -ErrorAction Stop | Select-Object AntivirusEnabled,AntispywareEnabled,RealTimeProtectionEnabled,BehaviorMonitorEnabled,AntivirusSignatureLastUpdated | ConvertTo-Json -Compress`}},
			{Key: "defender_threats", Name: "Recent Defender threats", Command: "powershell", Args: []string{"-NoProfile", "-NonInteractive", "-Command", prefix + `$start=(Get-Date).AddHours(-24); $e=@(Get-MpThreatDetection -ErrorAction SilentlyContinue | Where-Object {$_.InitialDetectionTime -ge $start} | Select-Object ThreatID,InitialDetectionTime,LastThreatStatusChangeTime,ActionSuccess,Resources); $e | ConvertTo-Json -Compress; if($e.Count -eq 0){'[]'}`}},
			{Key: "firewall", Name: "Firewall profiles", Command: "powershell", Args: []string{"-NoProfile", "-NonInteractive", "-Command", prefix + `Get-NetFirewallProfile | Select-Object Name,Enabled,DefaultInboundAction,DefaultOutboundAction | ConvertTo-Json -Compress`}},
			{Key: "security_updates", Name: "Security updates", Command: "powershell", Args: []string{"-NoProfile", "-NonInteractive", "-Command", prefix + `Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 20 HotFixID,Description,InstalledOn | ConvertTo-Json -Compress`}},
		}
	}

	return []commandCheck{
		{Key: "system_health", Name: "System health", Command: "sh", Args: []string{"-c", `cpu=$(LC_ALL=C top -bn1 2>/dev/null | awk '/Cpu\(s\)|^%Cpu/{for(i=1;i<=NF;i++) if($i ~ /id/){gsub(/,/,"",$(i-1)); printf "%.1f",100-$(i-1); exit}}'); mem=$(free -b 2>/dev/null | awk '/^Mem:/{if($2>0) printf "%.1f",100*$3/$2}'); swap=$(free -b 2>/dev/null | awk '/^Swap:/{if($2>0) printf "%.1f",100*$3/$2; else printf "0.0"}'); [ -n "$cpu" ] || cpu=0; [ -n "$mem" ] || mem=0; [ -n "$swap" ] || swap=0; printf '{"CPUPercent":%s,"MemoryPercent":%s,"SwapPercent":%s}\n' "$cpu" "$mem" "$swap"`}},
		{Key: "disk", Name: "Disk", Command: "df", Args: []string{"-P", "-h"}},
		{Key: "processes", Name: "Processes", Command: "sh", Args: []string{"-c", `ps -eo pid,user,%cpu,%mem,comm,args --sort=-%cpu | head -n 80`}},
		{Key: "process_pressure", Name: "Process pressure", Command: "sh", Args: []string{"-c", `ps -eo pid=,comm=,%cpu=,%mem= --sort=-%cpu | head -n 30`}},
		{Key: "network", Name: "Network", Command: "sh", Args: []string{"-c", `ss -tunap 2>/dev/null || netstat -tunap 2>/dev/null`}},
		{Key: "login_history", Name: "Login history", Command: "sh", Args: []string{"-c", `last -ai -n 30 2>/dev/null`}},
		{Key: "failed_logins", Name: "Failed logins", Command: "sh", Args: []string{"-c", `lastb -ai -n 30 2>/dev/null`}},
		{Key: "users", Name: "Local users", Command: "sh", Args: []string{"-c", `getent passwd 2>/dev/null`}},
		{Key: "services", Name: "Auto-start services", Command: "sh", Args: []string{"-c", `systemctl list-unit-files --type=service --state=enabled --no-legend --no-pager 2>/dev/null || true`}},
		{Key: "security_updates", Name: "Security updates", Command: "sh", Args: []string{"-c", `(command -v apt >/dev/null && apt list --upgradable 2>/dev/null | head -n 50) || (command -v dnf >/dev/null && dnf check-update --security 2>/dev/null | head -n 50) || true`}},
	}
}

func runCheck(ctx context.Context, check commandCheck) CheckResult {
	cmd := exec.CommandContext(ctx, check.Command, check.Args...)
	output, err := cmd.CombinedOutput()
	text := strings.TrimSpace(string(output))
	result := CheckResult{Key: check.Key, Name: check.Name, Status: StatusNormal, Summary: "collected", Raw: text}
	if err != nil {
		result.Status = StatusUnknown
		result.Summary = "check unavailable"
		if text == "" { text = err.Error() } else { text = fmt.Sprintf("%s\n%s", text, err) }
		result.Raw = text
	}
	hash := sha256.Sum256([]byte(result.Raw))
	result.Fingerprint = hex.EncodeToString(hash[:])
	return result
}
