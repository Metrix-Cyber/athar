//go:build windows

package windows

import (
	"context"
	"fmt"

	"golang.org/x/sys/windows/registry"

	"github.com/Metrix-Cyber/athar/internal/check"
	"github.com/Metrix-Cyber/athar/internal/finding"
)

// ECC 2-6 covers mobile device security. On a managed Windows endpoint the
// assessable parts are whether the device is centrally managed and whether
// removable media is required to be encrypted.
// 2-6-3-1 requires separation and encryption of entity data on mobile
// devices; the removable-media encryption policy is direct evidence of it.
var deviceCodes = []string{"2-6-2", "2-6-3-1", "2-6-3-2"}

func init() {
	for _, c := range []check.Check{
		{ID: "win.device.management", Subdomain: "2-6", ControlCodes: deviceCodes,
			Platforms: []string{"windows"}, Run: deviceManagement},
		{ID: "win.device.removable_encryption", Subdomain: "2-6", ControlCodes: deviceCodes,
			Platforms: []string{"windows"}, Run: removableEncryption},
	} {
		check.Register(c)
	}
}

// deviceManagement reports whether the host is enrolled in central management.
//
// An unmanaged endpoint cannot receive policy, which undermines most other
// technical controls: settings verified today can be changed tomorrow with
// nothing to detect or correct the drift.
func deviceManagement(ctx context.Context) []finding.Finding {
	f := finding.New("win.device.management", "Central device management", "2-6", deviceCodes)

	// MDM enrolment writes provider entries under this key.
	const enrollments = `SOFTWARE\Microsoft\Enrollments`
	var providers []string
	if k, err := registry.OpenKey(registry.LOCAL_MACHINE, enrollments,
		registry.ENUMERATE_SUB_KEYS); err == nil {
		names, _ := k.ReadSubKeyNames(-1)
		k.Close()
		for _, n := range names {
			if name, err := regString(enrollments+`\`+n, "ProviderID"); err == nil && name != "" {
				providers = append(providers, name)
			}
		}
	}

	// Domain membership is the other form of central management.
	domain, _ := regString(`SYSTEM\CurrentControlSet\Services\Tcpip\Parameters`, "Domain")
	joined := domain != ""

	f = f.With("mdm_providers", providers).
		With("domain_joined", joined).
		With("domain", domain)

	if len(providers) > 0 || joined {
		how := "domain membership"
		if len(providers) > 0 {
			how = "MDM enrolment (" + joinList(providers) + ")"
		}
		return []finding.Finding{f.Passed(fmt.Sprintf(
			"The host is centrally managed via %s. Policy coverage and compliance enforcement on the management platform still require verification.", how))}
	}

	return []finding.Finding{f.Failed(finding.Medium,
		"The host is neither domain joined nor enrolled in mobile device management. Security configuration cannot be centrally enforced, so settings verified now may drift without detection.",
		"Enrol the device in central management (domain or MDM) so security policy is applied and monitored.")}
}

// removableEncryption checks whether removable drives must be encrypted before
// they can be written to.
func removableEncryption(ctx context.Context) []finding.Finding {
	f := finding.New("win.device.removable_encryption",
		"Removable media encryption policy", "2-6", deviceCodes)

	const fve = `SOFTWARE\Policies\Microsoft\FVE`
	deny, present, err := dwordOr(fve, "RDVDenyWriteAccess", 0)
	if err != nil {
		return []finding.Finding{f.Undetermined(err)}
	}
	f = f.With("deny_write_to_unencrypted_removable", present && deny == 1)

	if !present || deny != 1 {
		return []finding.Finding{f.Failed(finding.Medium,
			"Write access to unencrypted removable drives is not denied by policy, so entity data can be copied to unprotected media.",
			"Enable 'Deny write access to removable drives not protected by BitLocker' by Group Policy.")}
	}
	return []finding.Finding{f.Passed(
		"Write access to removable drives requires BitLocker protection.")}
}
