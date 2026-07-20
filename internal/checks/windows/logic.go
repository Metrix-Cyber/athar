package windows

import (
	"strings"

	"github.com/Metrix-Cyber/athar/internal/finding"
)

// This file carries no build constraint deliberately.
//
// The Windows checks read the registry and call Win32 APIs, which cannot be
// exercised off Windows or without a specific host state. The decisions those
// checks make, however, are pure functions of values already read — and the
// decisions are where every bug found so far actually lived. Keeping them here
// means they compile and are tested on every platform, and a contributor on
// Linux can change a threshold without flying blind.

// booleanTrue interprets the return value of a Win32 function declared as
// BOOLEAN.
//
// BOOLEAN is a single byte, not a 4-byte BOOL. The syscall return register
// carries unrelated data in its upper bytes, so comparing the full uintptr
// against zero reads a failed call as success. That happened:
// AuditQuerySystemPolicy returned 957970821120 on failure — low byte zero —
// and the code then dereferenced a nil output pointer inside a customer-facing
// report. Mask to the low byte for any BOOLEAN-returning function.
func booleanTrue(r uintptr) bool { return r&0xFF != 0 }

// buildNumber parses a Windows CurrentBuild value, returning 0 when it is not
// a plain number.
func buildNumber(s string) int {
	if s == "" {
		return 0
	}
	n := 0
	for _, r := range s {
		if r < '0' || r > '9' {
			return 0
		}
		n = n*10 + int(r-'0')
	}
	return n
}

// win11MinBuild is the first Windows 11 build number.
const win11MinBuild = 22000

// normalizeProductName corrects the registry's product name.
//
// Microsoft never updated ProductName for Windows 11, so the registry reports
// "Windows 10" on every Windows 11 host. An asset inventory naming the wrong
// operating system is the first thing an assessor cross-checks, and it
// undermines confidence in everything else in the report.
// NormalizeProductName is exported so the scanner can label a host with the
// same corrected product name the checks reason about, rather than the raw
// registry value.
func NormalizeProductName(product, build string) string {
	if buildNumber(build) >= win11MinBuild && strings.HasPrefix(product, "Windows 10") {
		return "Windows 11" + strings.TrimPrefix(product, "Windows 10")
	}
	return product
}

// Patch currency thresholds. ECC requires patch management to exist and be
// effective but states no interval, so these are configurable policy rather
// than framework text — an assessor sets them per client.
const (
	patchCriticalDays = 90
	patchHighDays     = 35
)

// patchSeverity maps days since the last update to a severity, and reports
// whether the state is a failure at all.
func patchSeverity(days int) (finding.Severity, bool) {
	switch {
	case days > patchCriticalDays:
		return finding.Critical, true
	case days > patchHighDays:
		return finding.High, true
	}
	return finding.Info, false
}

// Password policy baseline.
const (
	minPasswordLength  = 8
	minPasswordHistory = 5
)

// timeqForever marks "never expires" in NetUserModalsGet output.
const timeqForever = 0xFFFFFFFF

// passwordPolicyProblems lists the ways a local password policy falls short.
// Returning the reasons rather than a boolean lets the finding say precisely
// what is wrong, which is what makes it actionable.
func passwordPolicyProblems(minLen, historyLen, maxAgeSeconds uint32) []string {
	var problems []string
	if minLen < minPasswordLength {
		problems = append(problems, "minimum length is "+itoa(int(minLen))+
			" (expected at least "+itoa(minPasswordLength)+")")
	}
	if historyLen < minPasswordHistory {
		problems = append(problems, "password history is "+itoa(int(historyLen))+
			" (expected at least "+itoa(minPasswordHistory)+")")
	}
	if maxAgeSeconds == timeqForever {
		problems = append(problems, "passwords never expire")
	}
	return problems
}

// wirelessProfile is one saved network.
type wirelessProfile struct {
	SSID, Auth, Encryption string
}

// classify grades a saved wireless profile.
//
// "open" and "WEP" are unambiguous failures. WPA-Personal and TKIP are
// deprecated but still encrypted, so they are graded separately — reporting a
// legacy-but-encrypted network as equivalent to an open one would not survive
// assessor review.
func classify(p wirelessProfile) string {
	auth := strings.ToLower(p.Auth)
	enc := strings.ToLower(p.Encryption)

	switch {
	case auth == "open" && (enc == "none" || enc == ""):
		return "open"
	case strings.Contains(enc, "wep") || auth == "shared":
		return "wep"
	case auth == "wpapsk" || strings.Contains(enc, "tkip"):
		return "legacy"
	}
	return ""
}

// ntohs converts a network byte order port as returned by the IP helper API.
func ntohs(p uint32) uint16 {
	return uint16(p<<8) | uint16(p>>8&0xff)
}

// isPublicResolver reports whether a DNS server is a well-known public
// resolver, which prevents the entity filtering, logging or inspecting its own
// name resolution.
func isPublicResolver(addr string) (string, bool) {
	operator, ok := publicResolvers[addr]
	return operator, ok
}

var publicResolvers = map[string]string{
	"8.8.8.8": "Google", "8.8.4.4": "Google",
	"1.1.1.1": "Cloudflare", "1.0.0.1": "Cloudflare",
	"9.9.9.9": "Quad9", "149.112.112.112": "Quad9",
	"208.67.222.222": "OpenDNS", "208.67.220.220": "OpenDNS",
}

// joinList renders a list in prose form.
func joinList(items []string) string {
	switch len(items) {
	case 0:
		return ""
	case 1:
		return items[0]
	}
	s := ""
	for i, it := range items {
		switch {
		case i == 0:
			s = it
		case i == len(items)-1:
			s += " and " + it
		default:
			s += ", " + it
		}
	}
	return s
}

// lower is a minimal ASCII lowercase; the Office policy tree uses lowercase
// application names.
func lower(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + 32
		}
	}
	return string(b)
}

func joinCount(n int) string {
	if n == 1 {
		return "One primitive"
	}
	return itoa(n) + " primitives"
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	if neg {
		return "-" + string(b)
	}
	return string(b)
}

func policySuffix(configured bool) string {
	if configured {
		return ". BitLocker policy is configured on this host"
	}
	return ". No BitLocker Group Policy configuration was found, indicating encryption is not centrally enforced"
}
