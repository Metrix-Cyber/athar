//go:build windows

package windows

import (
	"context"
	"fmt"

	"github.com/Metrix-Cyber/athar/internal/check"
	"github.com/Metrix-Cyber/athar/internal/finding"
)

// ECC 2-9 covers backup and recovery management.
var backupCodes = []string{"2-9-2"}

func init() {
	check.Register(check.Check{
		ID: "win.backup.capability", Subdomain: "2-9", ControlCodes: backupCodes,
		Platforms: []string{"windows"}, Run: backupCapability,
	})
}

// backupAgents are services indicating a backup product is deployed.
var backupAgents = map[string]string{
	"Veeam Agent":               "VeeamEndpointBackupSvc",
	"Veeam Backup Service":      "VeeamBackupSvc",
	"Acronis Agent":             "AcronisAgent",
	"Commvault":                 "GxCVD(Instance001)",
	"Veritas Backup Exec Agent": "BackupExecAgentAccelerator",
	"Windows Server Backup":     "wbengine",
	"Azure Recovery Services":   "OBRecoveryServicesManagementAgent",
	"Cohesity Agent":            "CohesityAgent",
	"Rubrik Backup Service":     "Rubrik Backup Service",
}

// backupCapability reports whether any backup mechanism is present.
//
// This check is deliberately limited in what it claims. Presence of a backup
// agent is not evidence of a working backup, and ECC 2-9 requires backups to
// be performed, protected and restore-tested — none of which a host scan can
// determine. The finding therefore reports capability and explicitly hands the
// rest to the assessor rather than implying a passing control.
func backupCapability(ctx context.Context) []finding.Finding {
	f := finding.New("win.backup.capability", "Backup capability", "2-9", backupCodes)

	var found []string
	for label, svc := range backupAgents {
		running, present, err := serviceState(svc)
		if err != nil || !present {
			continue
		}
		found = append(found, label)
		f = f.With("agent_"+label+"_running", running)
	}

	// Volume Shadow Copy underpins most Windows backup mechanisms. Its
	// presence alone proves nothing, but its absence is worth noting.
	vssRunning, vssPresent, _ := serviceState("VSS")
	f = f.With("vss_service_present", vssPresent).
		With("vss_service_running", vssRunning).
		With("backup_products_detected", found)

	if len(found) > 0 {
		return []finding.Finding{f.Passed(fmt.Sprintf(
			"Backup tooling is present on this host (%s). This confirms capability only: ECC 2-9 additionally requires that backups are performed on schedule, protected against tampering, and periodically restore-tested, none of which can be determined from the host and all of which require assessor verification.",
			joinList(found)))}
	}

	return []finding.Finding{f.Failed(finding.Medium,
		"No backup agent or backup service was detected on this host. Where backup is provided by a hypervisor, storage-array or cloud-level mechanism this may be expected, but it cannot be evidenced from the operating system and must be confirmed.",
		"Confirm how this host is backed up, and evidence backup scheduling, protection and periodic restore testing.")}
}
