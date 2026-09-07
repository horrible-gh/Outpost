package patrol

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os/exec"
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
	if err != nil {
		return
	}
	raw := strings.TrimSpace(string(output))
	if raw == "" {
		return
	}
	for i := range snapshot.Checks {
		if snapshot.Checks[i].Key != "system_health" {
			continue
		}
		snapshot.Checks[i].Raw = raw
		snapshot.Checks[i].Summary = "collected"
		snapshot.Checks[i].Status = StatusNormal
		hash := sha256.Sum256([]byte(raw))
		snapshot.Checks[i].Fingerprint = hex.EncodeToString(hash[:])
		return
	}
}
