//go:build windows

package windows

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"time"

	"golang.org/x/sys/windows/registry"

	"github.com/Metrix-Cyber/athar/internal/check"
	"github.com/Metrix-Cyber/athar/internal/finding"
)

// ECC 2-3-3-1 is "Protection from viruses, suspicious programs and activities,
// and malware on workstations and servers"; 2-3-3-2 is "Strict restriction on
// the use of external storage media and their security".
var (
	malwareCodes = []string{"2-3-2", "2-3-3-1"}
	mediaCodes   = []string{"2-3-2", "2-3-3-2"}
)

func init() {
	for _, c := range []check.Check{
		{ID: "win.epp.antimalware", Subdomain: "2-3", ControlCodes: malwareCodes,
			Platforms: []string{"windows"}, Run: antimalware},
		{ID: "win.epp.removable_media", Subdomain: "2-3", ControlCodes: mediaCodes,
			Platforms: []string{"windows"}, Run: removableMedia},
	} {
		check.Register(c)
	}
}

const defenderBase = `SOFTWARE\Microsoft\Windows Defender`

// antimalware reports endpoint protection state and signature freshness.
//
// Accuracy note: the registry describes Microsoft Defender specifically. Where
// a third-party product is installed, Defender steps aside and its own state
// stops being meaningful — so a disabled Defender is reported as undetermined
// rather than as a failure. Failing a host that is in fact protected by a
// managed EDR product would be a false positive on precisely the enterprise
// estates this scanner is aimed at.
func antimalware(ctx context.Context) []finding.Finding {
	f := finding.New("win.epp.antimalware", "Endpoint anti-malware protection", "2-3", malwareCodes)

	running, present, err := serviceState("WinDefend")
	if err != nil {
		return []finding.Finding{f.Undetermined(err)}
	}
	f = f.With("defender_service_present", present).With("defender_service_running", running)

	// Explicit policy disable is worth surfacing regardless of service state.
	disabled, _, _ := dwordOr(defenderBase, "DisableAntiSpyware", 0)
	f = f.With("defender_disabled_by_policy", disabled == 1)

	if !present || !running || disabled == 1 {
		return []finding.Finding{f.Undetermined(errors.New(
			"Microsoft Defender is not active on this host. This may be correct if a " +
				"third-party endpoint protection product is deployed, which this scan " +
				"cannot confirm; verify the anti-malware product in use and its status"))}
	}

	// Signature freshness. SignaturesLastUpdated is a little-endian FILETIME.
	last, err := defenderSignatureTime()
	if err != nil {
		return []finding.Finding{f.Passed(
			"Microsoft Defender is running, but signature age could not be determined.")}
	}

	age := int(time.Since(last).Hours() / 24)
	f = f.With("signatures_last_updated", last.Format(time.RFC3339)).
		With("signature_age_days", age)

	if v, err := regString(defenderBase+`\Signature Updates`, "AVSignatureVersion"); err == nil {
		f = f.With("signature_version", v)
	}

	switch {
	case age > 7:
		return []finding.Finding{f.Failed(finding.High,
			fmt.Sprintf("Microsoft Defender is running but its signatures are %d days old (last updated %s). Detection of recent malware is degraded.",
				age, last.Format("2 January 2006")),
			"Investigate why signature updates are not being received and update definitions.")}
	case age > 2:
		return []finding.Finding{f.Failed(finding.Medium,
			fmt.Sprintf("Microsoft Defender signatures are %d days old (last updated %s).",
				age, last.Format("2 January 2006")),
			"Confirm the host is receiving definition updates on schedule.")}
	default:
		return []finding.Finding{f.Passed(fmt.Sprintf(
			"Microsoft Defender is running with signatures updated %s.",
			last.Format("2 January 2006")))}
	}
}

// defenderSignatureTime decodes the FILETIME stored under Signature Updates.
func defenderSignatureTime() (time.Time, error) {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE,
		defenderBase+`\Signature Updates`, registry.QUERY_VALUE)
	if err != nil {
		return time.Time{}, err
	}
	defer k.Close()

	buf, _, err := k.GetBinaryValue("SignaturesLastUpdated")
	if err != nil {
		return time.Time{}, err
	}
	if len(buf) < 8 {
		return time.Time{}, fmt.Errorf("SignaturesLastUpdated is %d bytes, expected 8", len(buf))
	}

	// FILETIME: 100-nanosecond intervals since 1601-01-01 UTC.
	ft := binary.LittleEndian.Uint64(buf[:8])
	const (
		ticksPerSecond = 10_000_000
		epochDelta     = 11_644_473_600 // seconds between 1601 and 1970
	)
	secs := int64(ft/ticksPerSecond) - epochDelta
	if secs <= 0 {
		return time.Time{}, errors.New("SignaturesLastUpdated holds an implausible timestamp")
	}
	return time.Unix(secs, 0).UTC(), nil
}

// removableMedia checks restrictions on external storage, which ECC 2-3-3-2
// calls out explicitly.
func removableMedia(ctx context.Context) []finding.Finding {
	var out []finding.Finding

	// AutoRun: NoDriveTypeAutoRun 0xFF disables AutoPlay on all drive types.
	// Absent leaves the OS default, which does not disable it for all types.
	ar := finding.New("win.epp.autorun", "AutoPlay restriction", "2-3", mediaCodes)
	v, present, err := dwordOr(
		`SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer`, "NoDriveTypeAutoRun", 0)
	switch {
	case err != nil:
		out = append(out, ar.Undetermined(err))
	case !present || v != 0xFF:
		out = append(out, ar.With("no_drive_type_autorun", v).With("policy_configured", present).
			Failed(finding.Medium,
				"AutoPlay is not disabled for all drive types, allowing content on removable media to execute automatically when connected.",
				"Set the 'Turn off AutoPlay' policy to All drives (NoDriveTypeAutoRun = 0xFF)."))
	default:
		out = append(out, ar.With("no_drive_type_autorun", v).
			Passed("AutoPlay is disabled for all drive types."))
	}

	// Removable storage write/read denial via Group Policy.
	rs := finding.New("win.epp.removable_storage", "Removable storage restriction", "2-3", mediaCodes)
	const rsPath = `SOFTWARE\Policies\Microsoft\Windows\RemovableStorageDevices`
	denyAll, denyPresent, err := dwordOr(rsPath+`\{53f5630d-b6bf-11d0-94f2-00a0c91efb8b}`, "Deny_All", 0)
	if err != nil {
		out = append(out, rs.Undetermined(err))
	} else if !denyPresent || denyAll != 1 {
		out = append(out, rs.With("removable_storage_denied", false).
			Failed(finding.Low,
				"No Group Policy restriction on removable storage devices was found. ECC requires strict restriction on the use of external storage media; where such media is permitted by design, this should be evidenced by policy and compensating controls.",
				"Apply removable storage restrictions by Group Policy, or document the business justification and compensating controls."))
	} else {
		out = append(out, rs.With("removable_storage_denied", true).
			Passed("Removable storage devices are denied by Group Policy."))
	}

	return out
}
