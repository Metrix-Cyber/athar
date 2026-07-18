//go:build windows

package windows

import (
	"context"
	"fmt"

	"github.com/Metrix-Cyber/athar/internal/check"
	"github.com/Metrix-Cyber/athar/internal/finding"
)

// ECC 2-5-3-5 is "Restricting and managing network services, protocols, and
// ports" — the control these checks provide evidence toward. 2-5-2 covers
// implementation of network security requirements generally.
var netCodes = []string{"2-5-2", "2-5-3-5"}

func init() {
	for _, c := range []check.Check{
		{ID: "win.net.firewall", Subdomain: "2-5", ControlCodes: netCodes,
			Platforms: []string{"windows"}, Run: firewallProfiles},
		{ID: "win.net.smb", Subdomain: "2-5", ControlCodes: netCodes,
			Platforms: []string{"windows"}, Run: smbConfig},
		{ID: "win.net.rdp", Subdomain: "2-5", ControlCodes: netCodes,
			Platforms: []string{"windows"}, Run: rdpConfig},
		{ID: "win.net.name_resolution", Subdomain: "2-5", ControlCodes: netCodes,
			Platforms: []string{"windows"}, Run: nameResolution},
	} {
		check.Register(c)
	}
}

const fwBase = `SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy`

// Group Policy settings override the local ones and must be read first,
// otherwise a domain-managed host reports its ignored local configuration.
const fwPolicyBase = `SOFTWARE\Policies\Microsoft\WindowsFirewall`

// firewallProfiles checks that Windows Firewall is enabled on every profile.
func firewallProfiles(ctx context.Context) []finding.Finding {
	profiles := []struct{ key, name string }{
		{"DomainProfile", "Domain"},
		{"StandardProfile", "Private"},
		{"PublicProfile", "Public"},
	}

	f := finding.New("win.net.firewall", "Windows Firewall state", "2-5", netCodes)

	var disabled []string
	for _, p := range profiles {
		// Policy value wins where present.
		v, present, err := dwordOr(fwPolicyBase+`\`+p.key, "EnableFirewall", 0)
		if err != nil || !present {
			// Fall back to the local profile setting. Absent defaults to
			// enabled on supported Windows versions.
			v, _, err = dwordOr(fwBase+`\`+p.key, "EnableFirewall", 1)
			if err != nil {
				return []finding.Finding{f.Undetermined(
					fmt.Errorf("reading %s profile: %w", p.name, err))}
			}
		}
		f = f.With(p.name+"_enabled", v == 1)
		if v != 1 {
			disabled = append(disabled, p.name)
		}
	}

	if len(disabled) > 0 {
		return []finding.Finding{f.Failed(finding.High,
			fmt.Sprintf("Windows Firewall is disabled on the %s profile(s). Network services on this host are unfiltered on those networks.",
				joinList(disabled)),
			"Enable Windows Firewall on all three profiles (Domain, Private and Public).")}
	}
	return []finding.Finding{f.Passed("Windows Firewall is enabled on all three profiles.")}
}

const lanmanServer = `SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters`

// smbConfig checks for SMBv1 and for SMB signing enforcement.
func smbConfig(ctx context.Context) []finding.Finding {
	var out []finding.Finding

	// SMBv1 — deprecated and the vector for WannaCry/NotPetya. Absent on
	// modern Windows means the feature is removed; explicitly set to 1 means
	// it has been turned back on.
	v1 := finding.New("win.net.smbv1", "SMBv1 protocol", "2-5", netCodes)
	smb1, present, err := dwordOr(lanmanServer, "SMB1", 0)
	switch {
	case err != nil:
		out = append(out, v1.Undetermined(err))
	case present && smb1 == 1:
		out = append(out, v1.With("smb1_server_enabled", true).Failed(finding.Critical,
			"SMBv1 is explicitly enabled on the SMB server. The protocol is deprecated, unpatchable against known attacks, and should not be present on any network.",
			"Disable SMBv1 and remove the SMB 1.0/CIFS Windows feature."))
	default:
		out = append(out, v1.With("smb1_server_enabled", false).
			Passed("SMBv1 is not enabled on the SMB server."))
	}

	// SMB signing — prevents relay and tampering on SMB sessions.
	sign := finding.New("win.net.smb_signing", "SMB signing enforcement", "2-5", netCodes)
	req, _, err := dwordOr(lanmanServer, "RequireSecuritySignature", 0)
	if err != nil {
		out = append(out, sign.Undetermined(err))
	} else if req != 1 {
		out = append(out, sign.With("require_security_signature", false).Failed(finding.Medium,
			"SMB signing is not required by the server, allowing SMB sessions to be relayed or tampered with by an attacker on the same network.",
			"Require SMB signing on the server (RequireSecuritySignature = 1)."))
	} else {
		out = append(out, sign.With("require_security_signature", true).
			Passed("SMB signing is required by the server."))
	}

	return out
}

const tsBase = `SYSTEM\CurrentControlSet\Control\Terminal Server`

// rdpConfig reports whether RDP is exposed and, if so, whether Network Level
// Authentication is enforced.
func rdpConfig(ctx context.Context) []finding.Finding {
	f := finding.New("win.net.rdp", "Remote Desktop exposure", "2-5", netCodes)

	// fDenyTSConnections: 1 = RDP refused, 0 = RDP accepted.
	deny, _, err := dwordOr(tsBase, "fDenyTSConnections", 1)
	if err != nil {
		return []finding.Finding{f.Undetermined(err)}
	}
	if deny == 1 {
		return []finding.Finding{f.With("rdp_enabled", false).
			Passed("Remote Desktop is disabled on this host.")}
	}

	f = f.With("rdp_enabled", true)

	// NLA forces authentication before a session is established, which blocks
	// pre-auth attacks against the RDP stack.
	nla, _, err := dwordOr(tsBase+`\WinStations\RDP-Tcp`, "UserAuthentication", 0)
	if err != nil {
		return []finding.Finding{f.Undetermined(err)}
	}
	f = f.With("network_level_authentication", nla == 1)

	if nla != 1 {
		return []finding.Finding{f.Failed(finding.High,
			"Remote Desktop is enabled without Network Level Authentication, so the RDP service can be reached before any credentials are supplied.",
			"Require Network Level Authentication for Remote Desktop, and restrict RDP access to management networks only.")}
	}
	return []finding.Finding{f.Failed(finding.Low,
		"Remote Desktop is enabled with Network Level Authentication required. This is the safer configuration, but remote administrative access should still be restricted to management networks and reviewed against need.",
		"Confirm RDP exposure is intentional and restricted by firewall rule to authorised source addresses.")}
}

// nameResolution checks legacy broadcast name-resolution protocols, which
// allow credential interception on a local network.
func nameResolution(ctx context.Context) []finding.Finding {
	f := finding.New("win.net.name_resolution", "Legacy name resolution protocols", "2-5", netCodes)

	// EnableMulticast = 0 disables LLMNR. Absent means LLMNR is active.
	llmnr, present, err := dwordOr(
		`SOFTWARE\Policies\Microsoft\Windows NT\DNSClient`, "EnableMulticast", 1)
	if err != nil {
		return []finding.Finding{f.Undetermined(err)}
	}
	enabled := llmnr == 1
	f = f.With("llmnr_enabled", enabled).With("llmnr_policy_configured", present)

	if enabled {
		return []finding.Finding{f.Failed(finding.Medium,
			"LLMNR is enabled. It permits an attacker on the same network segment to answer name-resolution broadcasts and capture authentication material.",
			"Disable LLMNR via Group Policy (Turn off multicast name resolution), and disable NetBIOS over TCP/IP where it is not required.")}
	}
	return []finding.Finding{f.Passed("LLMNR is disabled by policy.")}
}
