//go:build windows

package windows

import (
	"context"
	"errors"
	"fmt"

	"golang.org/x/sys/windows"

	"github.com/Metrix-Cyber/athar/internal/check"
	"github.com/Metrix-Cyber/athar/internal/finding"
)

// ECC 2-7-2 requires protection of data and information to be implemented
// based on its classification. Disk encryption is evidence toward protection
// of data at rest; whether the level of protection matches the entity's data
// classification is an assessor judgement.
var dataCodes = []string{"2-7-2"}

func init() {
	check.Register(check.Check{
		ID: "win.data.disk_encryption", Subdomain: "2-7", ControlCodes: dataCodes,
		Platforms: []string{"windows"}, NeedsAdmin: true, Run: diskEncryption,
	})
}

// diskEncryption reports BitLocker volume protection state.
//
// Volume encryption status is only readable through interfaces that require
// elevation (Win32_EncryptableVolume, manage-bde). Unelevated, the honest
// answer is that it could not be determined — reporting "not encrypted"
// because the state was unreadable would be a false failure on a correctly
// encrypted host, and reporting a pass would be far worse.
func diskEncryption(ctx context.Context) []finding.Finding {
	f := finding.New("win.data.disk_encryption", "Disk encryption (BitLocker)", "2-7", dataCodes)

	running, present, err := serviceState("BDESVC")
	if err != nil {
		return []finding.Finding{f.Undetermined(err)}
	}
	f = f.With("bitlocker_service_present", present).
		With("bitlocker_service_running", running)

	// Policy configuration is readable unelevated and is itself useful
	// evidence: its absence means encryption is not being centrally enforced,
	// whatever the state of any individual volume.
	const fvePolicy = `SOFTWARE\Policies\Microsoft\FVE`
	policyConfigured := keyExists(fvePolicy)
	f = f.With("bitlocker_policy_configured", policyConfigured)

	if !present {
		return []finding.Finding{f.Failed(finding.High,
			"The BitLocker service is not present on this host, so volume encryption is unavailable. Data at rest is unprotected if the device is lost or stolen.",
			"Deploy an operating system edition supporting BitLocker, or evidence an equivalent full-disk encryption product.")}
	}

	// Per-volume state comes from WMI, which requires elevation. Without it the
	// honest answer is that we do not know: reporting "not encrypted" for a
	// volume we could not inspect would be a false finding on a correctly
	// protected host.
	if !windows.GetCurrentProcessToken().IsElevated() {
		return []finding.Finding{f.Undetermined(errors.New(
			"volume encryption status could not be read without administrative " +
				"privileges" + policySuffix(policyConfigured)))}
	}

	volumes, err := encryptableVolumes()
	if err != nil {
		return []finding.Finding{f.Undetermined(err)}
	}
	if len(volumes) == 0 {
		return []finding.Finding{f.Undetermined(errors.New(
			"no encryptable volumes were reported by this host" +
				policySuffix(policyConfigured)))}
	}

	var protected, unprotected, unknown []string
	for _, v := range volumes {
		switch {
		case v.Protected:
			protected = append(protected, fmt.Sprintf("%s (%s)", v.Drive, v.Method))
		case v.Unknown:
			unknown = append(unknown, v.Drive)
		default:
			unprotected = append(unprotected, v.Drive)
		}
	}

	f = f.With("volumes_total", len(volumes)).
		With("volumes_protected", protected).
		With("volumes_unprotected", unprotected).
		With("volumes_unknown", unknown)

	switch {
	case len(unprotected) > 0:
		return []finding.Finding{f.Failed(finding.High,
			fmt.Sprintf("%d of %d volume(s) are not protected by BitLocker: %s. Data at rest on those volumes is readable if the device or disk is lost, stolen or disposed of.",
				len(unprotected), len(volumes), joinList(unprotected)),
			"Enable BitLocker on all fixed volumes, and escrow recovery keys to a managed location.")}

	case len(unknown) > 0:
		return []finding.Finding{f.Failed(finding.Medium,
			fmt.Sprintf("%d volume(s) report an indeterminate protection state: %s. Encryption may be in progress or suspended.",
				len(unknown), joinList(unknown)),
			"Confirm the encryption state of these volumes and resume protection if it is suspended.")}

	default:
		return []finding.Finding{f.Passed(fmt.Sprintf(
			"All %d volume(s) are protected by BitLocker: %s.",
			len(volumes), joinList(protected)))}
	}
}

func policySuffix(configured bool) string {
	if configured {
		return ". BitLocker policy is configured on this host"
	}
	return ". No BitLocker Group Policy configuration was found, indicating encryption is not centrally enforced"
}
