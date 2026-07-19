//go:build windows

package windows

import (
	"context"
	"sort"
	"strings"

	"golang.org/x/sys/windows/registry"

	"github.com/Metrix-Cyber/athar/internal/check"
	"github.com/Metrix-Cyber/athar/internal/finding"
)

// ECC 2-8-3-1 requires "approved cryptographic systems and solutions standards
// and their technical and regulatory restrictions", aligned to the National
// Cryptographic Standards published by NCA. The scanner reports which
// algorithms the host will negotiate; whether that set meets the required
// standard level for the entity's data classification is an assessor decision.
var cipherCodes = []string{"2-8-2", "2-8-3-1"}

func init() {
	check.Register(check.Check{
		ID: "win.crypto.cipher_suites", Subdomain: "2-8", ControlCodes: cipherCodes,
		Platforms: []string{"windows"}, Run: cipherSuites,
	})
}

const schannelCiphers = `SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL`

// weakPrimitives are algorithms with published practical weaknesses. The list
// is deliberately conservative so that a finding is defensible rather than a
// matter of preference.
var weakPrimitives = map[string][]string{
	"Ciphers": {"DES", "RC2", "RC4", "NULL", "Triple DES"},
	"Hashes":  {"MD5"},
}

func cipherSuites(ctx context.Context) []finding.Finding {
	f := finding.New("win.crypto.cipher_suites", "Cryptographic algorithm configuration", "2-8", cipherCodes)

	var enabledWeak, disabledWeak, unconfigured []string

	for section, names := range weakPrimitives {
		for _, name := range names {
			path := schannelCiphers + `\` + section + `\` + name
			v, present, err := dwordOr(path, "Enabled", 0)
			label := section + `/` + name
			switch {
			case err != nil:
				continue
			case !present:
				unconfigured = append(unconfigured, label)
			case v == 0:
				disabledWeak = append(disabledWeak, label)
			default:
				enabledWeak = append(enabledWeak, label)
			}
		}
	}

	// The explicit cipher suite order, where a policy sets one.
	if order, err := regString(
		`SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002`,
		"Functions"); err == nil && order != "" {
		suites := strings.Split(order, ",")
		f = f.With("configured_cipher_suite_count", len(suites))

		var weakSuites []string
		for _, s := range suites {
			ls := strings.ToLower(strings.TrimSpace(s))
			for _, bad := range []string{"_rc4_", "_des_", "_null_", "_md5", "_3des_", "_export"} {
				if strings.Contains(ls, bad) {
					weakSuites = append(weakSuites, strings.TrimSpace(s))
					break
				}
			}
		}
		if len(weakSuites) > 0 {
			sort.Strings(weakSuites)
			f = f.With("weak_cipher_suites_permitted", weakSuites)
			enabledWeak = append(enabledWeak, weakSuites...)
		}
	}

	sort.Strings(enabledWeak)
	sort.Strings(unconfigured)
	f = f.With("weak_primitives_explicitly_enabled", enabledWeak).
		With("weak_primitives_explicitly_disabled", disabledWeak).
		With("not_explicitly_configured", unconfigured)

	if len(enabledWeak) > 0 {
		return []finding.Finding{f.Failed(finding.High,
			"Cryptographic primitives with known weaknesses are explicitly enabled: "+joinList(enabledWeak)+
				". Data in transit negotiated with these algorithms is not adequately protected.",
			"Disable DES, 3DES, RC2, RC4, NULL and MD5 under SCHANNEL, and restrict the cipher suite order to algorithms permitted by the National Cryptographic Standards.")}
	}

	if len(unconfigured) > 0 {
		return []finding.Finding{f.Passed(
			"No weak cryptographic primitive is explicitly enabled. " +
				joinCount(len(unconfigured)) + " are not explicitly configured and therefore follow operating system defaults, " +
				"which should be confirmed against the cryptographic standard level required for this entity's data classification.")}
	}

	return []finding.Finding{f.Passed(
		"Weak cryptographic primitives are explicitly disabled.")}
}

func joinCount(n int) string {
	switch n {
	case 1:
		return "One primitive"
	default:
		return itoa(n) + " primitives"
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

// unusedRegistryRef keeps the registry import explicit for future use in this
// file; the helpers in registry.go wrap all current access.
var _ = registry.LOCAL_MACHINE
