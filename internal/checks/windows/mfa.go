//go:build windows

package windows

import (
	"context"

	"github.com/Metrix-Cyber/athar/internal/check"
	"github.com/Metrix-Cyber/athar/internal/finding"
)

// ECC 2-2-3-2 requires "multi-factor authentication ... for remote access and
// for privileged accounts".
//
// A host scan cannot confirm that MFA is enforced — that decision lives in the
// identity provider, not on the endpoint. What it can do is report whether the
// host is configured to support and require stronger authentication, which is
// evidence toward the control rather than a verdict on it. This distinction is
// stated in the finding so an assessor is not misled into treating a pass here
// as MFA coverage.
var mfaCodes = []string{"2-2-2", "2-2-3-2"}

func init() {
	check.Register(check.Check{
		ID: "win.iam.strong_authentication", Subdomain: "2-2", ControlCodes: mfaCodes,
		Platforms: []string{"windows"}, Run: strongAuthentication,
	})
}

func strongAuthentication(ctx context.Context) []finding.Finding {
	f := finding.New("win.iam.strong_authentication",
		"Strong authentication capability", "2-2", mfaCodes)

	// Smart card requirement for interactive logon.
	scForce, scSet, _ := dwordOr(policySystem, "ScForceOption", 0)

	// Windows Hello for Business, which is a genuine second factor bound to
	// the device's TPM.
	whfb, whfbSet, _ := dwordOr(
		`SOFTWARE\Policies\Microsoft\PassportForWork`, "Enabled", 0)

	// Credential Guard protects derived credentials from theft, which is what
	// makes a second factor meaningful on a compromised host.
	credGuard, cgSet, _ := dwordOr(
		`SYSTEM\CurrentControlSet\Control\LSA`, "LsaCfgFlags", 0)

	// RDP requiring Network Level Authentication is the remote-access portion.
	nla, _, _ := dwordOr(tsBase+`\WinStations\RDP-Tcp`, "UserAuthentication", 0)
	rdpDeny, _, _ := dwordOr(tsBase, "fDenyTSConnections", 1)

	f = f.With("smart_card_required", scSet && scForce == 1).
		With("windows_hello_for_business_policy", whfbSet && whfb == 1).
		With("credential_guard_configured", cgSet && credGuard > 0).
		With("rdp_enabled", rdpDeny == 0).
		With("rdp_network_level_authentication", nla == 1)

	var mechanisms []string
	if scSet && scForce == 1 {
		mechanisms = append(mechanisms, "smart card required for logon")
	}
	if whfbSet && whfb == 1 {
		mechanisms = append(mechanisms, "Windows Hello for Business")
	}
	if cgSet && credGuard > 0 {
		mechanisms = append(mechanisms, "Credential Guard")
	}

	if len(mechanisms) == 0 {
		return []finding.Finding{f.Failed(finding.Medium,
			"No host-side strong authentication mechanism was found: neither smart card enforcement, Windows Hello for Business, nor Credential Guard is configured. "+
				"Whether multi-factor authentication is enforced for remote access and privileged accounts is determined by the identity provider and cannot be confirmed from this host — but no supporting endpoint configuration is present either.",
			"Deploy Windows Hello for Business or smart card authentication, enable Credential Guard, and evidence MFA enforcement at the identity provider for remote access and privileged accounts.")}
	}

	return []finding.Finding{f.Passed(
		"Host-side strong authentication is configured (" + joinList(mechanisms) + "). " +
			"This supports but does not evidence ECC 2-2-3-2: MFA enforcement for remote access and privileged accounts is set at the identity provider and must be confirmed there.")}
}
