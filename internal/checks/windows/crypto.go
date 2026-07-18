//go:build windows

package windows

import (
	"context"
	"fmt"
	"sort"

	"github.com/Metrix-Cyber/athar/internal/check"
	"github.com/Metrix-Cyber/athar/internal/finding"
)

// ECC 2-8-3-3 is "Encryption of data in-transit and at-rest, as per their
// classification and the relevant legislative and regulatory requirements".
// 2-8-2 covers implementation of cryptography requirements generally.
//
// Note that ECC 2-8-3 requires alignment with the National Cryptographic
// Standards published by NCA. This scanner reports the protocols the host has
// enabled; determining whether those meet the required standard level for the
// entity's data classification is an assessor judgement, not a scan result.
var cryptoCodes = []string{"2-8-2", "2-8-3-3"}

func init() {
	check.Register(check.Check{
		ID: "win.crypto.tls_protocols", Subdomain: "2-8", ControlCodes: cryptoCodes,
		Platforms: []string{"windows"}, Run: tlsProtocols,
	})
}

const schannel = `SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols`

// deprecated lists protocols that must not be enabled.
var deprecated = []string{"SSL 2.0", "SSL 3.0", "TLS 1.0", "TLS 1.1"}

// tlsProtocols reports which SCHANNEL protocols are explicitly configured.
//
// Absent values mean the host follows the operating system default, which
// varies by Windows build. The check therefore distinguishes "explicitly
// enabled" (a finding) from "not configured" (reported, but not asserted as a
// pass or a failure) rather than guessing the effective state — an assessor
// needs to know the difference, and a scanner that infers defaults will
// eventually infer them wrongly across a mixed estate.
func tlsProtocols(ctx context.Context) []finding.Finding {
	f := finding.New("win.crypto.tls_protocols", "TLS/SSL protocol configuration", "2-8", cryptoCodes)

	var (
		enabledWeak  []string
		unconfigured []string
	)

	for _, proto := range deprecated {
		for _, role := range []string{"Server", "Client"} {
			path := fmt.Sprintf(`%s\%s\%s`, schannel, proto, role)

			enabled, hasEnabled, err := dwordOr(path, "Enabled", 0)
			if err != nil {
				return []finding.Finding{f.Undetermined(err)}
			}
			disabledByDefault, hasDBD, _ := dwordOr(path, "DisabledByDefault", 1)

			label := proto + " (" + role + ")"
			switch {
			case !hasEnabled && !hasDBD:
				unconfigured = append(unconfigured, label)
			case enabled != 0 && disabledByDefault == 0:
				enabledWeak = append(enabledWeak, label)
				f = f.With(label, "explicitly enabled")
			default:
				f = f.With(label, "explicitly disabled")
			}
		}
	}

	// TLS 1.2 should be available. An explicit disable here would break
	// modern connectivity and is worth reporting.
	if v, present, err := dwordOr(schannel+`\TLS 1.2\Server`, "Enabled", 1); err == nil && present && v == 0 {
		f = f.With("TLS 1.2 (Server)", "explicitly disabled")
		enabledWeak = append(enabledWeak, "TLS 1.2 is explicitly disabled")
	}

	sort.Strings(enabledWeak)
	sort.Strings(unconfigured)
	f = f.With("not_explicitly_configured", unconfigured)

	if len(enabledWeak) > 0 {
		return []finding.Finding{f.Failed(finding.High,
			fmt.Sprintf("Deprecated TLS/SSL protocols are explicitly enabled on this host: %s. These protocols have known cryptographic weaknesses and should not carry data in transit.",
				joinList(enabledWeak)),
			"Disable SSL 2.0, SSL 3.0, TLS 1.0 and TLS 1.1 under SCHANNEL for both client and server roles, retaining TLS 1.2 and above.")}
	}

	if len(unconfigured) > 0 {
		return []finding.Finding{f.Passed(fmt.Sprintf(
			"No deprecated TLS/SSL protocol is explicitly enabled. %d protocol/role combination(s) are not explicitly configured and therefore follow the operating system default, which should be confirmed against the entity's required cryptographic standard level.",
			len(unconfigured)))}
	}
	return []finding.Finding{f.Passed(
		"All deprecated TLS/SSL protocols are explicitly disabled for both client and server roles.")}
}
