package patrol

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os/exec"
	"sort"
	"strings"
)

// RefineSnapshot applies OS-specific follow-up collection that is useful but
// should not complicate the baseline collector. Failures leave the original
// evidence untouched.
func RefineSnapshot(ctx context.Context, snapshot *Snapshot) {
	if snapshot == nil || snapshot.OS != "windows" {
		return
	}
	refineWindowsSystemHealth(ctx, snapshot)
	refineWindowsProcessSignatures(ctx, snapshot)
}

func refineWindowsSystemHealth(ctx context.Context, snapshot *Snapshot) {
	const script = `$OutputEncoding=[Console]::OutputEncoding=[Text.UTF8Encoding]::new(); ` +
		`$os=Get-CimInstance Win32_OperatingSystem; ` +
		`$cpuObj=Get-CimInstance Win32_PerfFormattedData_PerfOS_Processor -Filter "Name='_Total'" -ErrorAction Stop; ` +
		`$cpu=[double]$cpuObj.PercentProcessorTime; ` +
		`$mem=[double](100*(($os.TotalVisibleMemorySize-$os.FreePhysicalMemory)/$os.TotalVisibleMemorySize)); ` +
		`$pf=@(Get-CimInstance Win32_PageFileUsage); $swap=0.0; ` +
		`if($pf.Count -gt 0){$allocated=($pf|Measure-Object AllocatedBaseSize -Sum).Sum; $used=($pf|Measure-Object CurrentUsage -Sum).Sum; if($allocated -gt 0){$swap=[double](100*$used/$allocated)}}; ` +
		`[pscustomobject]@{CPUPercent=[math]::Round($cpu,1);MemoryPercent=[math]::Round($mem,1);SwapPercent=[math]::Round($swap,1)} | ConvertTo-Json -Compress`

	cmd := exec.CommandContext(ctx, "powershell", "-NoProfile", "-NonInteractive", "-Command", script)
	output, err := cmd.CombinedOutput()
	if err != nil { return }
	raw := strings.TrimSpace(string(output))
	if raw == "" { return }
	replaceOrAppendCheck(snapshot, CheckResult{Key: "system_health", Name: "System health", Status: StatusNormal, Summary: "collected", Raw: raw})
}

func refineWindowsProcessSignatures(ctx context.Context, snapshot *Snapshot) {
	processCheck, ok := checkByKey(*snapshot, "processes")
	if !ok || processCheck.Status != StatusNormal { return }

	var processes []processEntry
	if json.Unmarshal([]byte(processCheck.Raw), &processes) != nil {
		var one processEntry
		if json.Unmarshal([]byte(processCheck.Raw), &one) != nil || one.ExecutablePath == "" { return }
		processes = []processEntry{one}
	}

	paths := map[string]struct{}{}
	for _, p := range processes {
		path := strings.TrimSpace(p.ExecutablePath)
		lower := strings.ToLower(strings.ReplaceAll(path, "/", "\\"))
		if path == "" { continue }
		if strings.Contains(lower, "\\temp\\") || strings.Contains(lower, "\\downloads\\") || strings.HasPrefix(lower, "c:\\windows\\temp\\") {
			paths[path] = struct{}{}
		}
	}
	if len(paths) == 0 { return }

	ordered := make([]string, 0, len(paths))
	for path := range paths { ordered = append(ordered, path) }
	sort.Strings(ordered)
	if len(ordered) > 10 { ordered = ordered[:10] }

	quoted := make([]string, 0, len(ordered))
	for _, path := range ordered {
		quoted = append(quoted, "'"+strings.ReplaceAll(path, "'", "''")+"'")
	}
	script := `$OutputEncoding=[Console]::OutputEncoding=[Text.UTF8Encoding]::new(); $paths=@(` + strings.Join(quoted, ",") + `); ` +
		`$r=@($paths | ForEach-Object {$s=Get-AuthenticodeSignature -FilePath $_ -ErrorAction SilentlyContinue; [pscustomobject]@{Path=$_;Status=[string]$s.Status;Signer=if($s.SignerCertificate){$s.SignerCertificate.Subject}else{''}}}); ` +
		`$r | ConvertTo-Json -Compress; if($r.Count -eq 0){'[]'}`
	cmd := exec.CommandContext(ctx, "powershell", "-NoProfile", "-NonInteractive", "-Command", script)
	output, err := cmd.CombinedOutput()
	if err != nil { return }
	raw := strings.TrimSpace(string(output))
	if raw == "" { return }
	replaceOrAppendCheck(snapshot, CheckResult{Key: "process_signatures", Name: "Suspicious process signatures", Status: StatusNormal, Summary: "collected", Raw: raw})
}

func replaceOrAppendCheck(snapshot *Snapshot, check CheckResult) {
	hash := sha256.Sum256([]byte(check.Raw))
	check.Fingerprint = hex.EncodeToString(hash[:])
	for i := range snapshot.Checks {
		if snapshot.Checks[i].Key == check.Key {
			snapshot.Checks[i] = check
			return
		}
	}
	snapshot.Checks = append(snapshot.Checks, check)
}
