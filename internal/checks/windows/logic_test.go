package windows

import (
	"testing"

	"github.com/Metrix-Cyber/athar/internal/finding"
)

// These tests deliberately target the defects that actually shipped during
// development. Each one encodes a bug that reached a working build and was
// caught only by comparing output against an independent source — so each is a
// regression guard for a mistake already made once.

// AuditQuerySystemPolicy returns BOOLEAN, a single byte. The syscall return
// register held 957970821120 on a failed call — low byte zero — and comparing
// the full uintptr against zero read that as success, then dereferenced a nil
// output pointer inside a customer-facing report.
func TestBooleanTrueMasksToLowByte(t *testing.T) {
	cases := []struct {
		name string
		ret  uintptr
		want bool
	}{
		{"observed failure value with garbage upper bytes", 957970821120, false},
		{"clean failure", 0, false},
		{"clean success", 1, true},
		{"success with upper-byte garbage", 0xDEADBEEF00 | 1, true},
		{"failure with upper-byte garbage", 0xDEADBEEF00, false},
		{"low byte 0xFF is true", 0xFF, true},
		{"only bit 8 set is false", 0x100, false},
	}
	for _, c := range cases {
		if got := booleanTrue(c.ret); got != c.want {
			t.Errorf("%s: booleanTrue(%#x) = %v, want %v", c.name, c.ret, got, c.want)
		}
	}
}

// The registry reports "Windows 10" on every Windows 11 host because Microsoft
// never updated ProductName. An asset inventory naming the wrong operating
// system is the first thing an assessor cross-checks.
func TestNormalizeProductName(t *testing.T) {
	cases := []struct {
		product, build, want string
	}{
		// The case observed on the development machine.
		{"Windows 10 Home", "26200", "Windows 11 Home"},
		{"Windows 10 Pro", "22000", "Windows 11 Pro"},
		{"Windows 10 Enterprise", "22631", "Windows 11 Enterprise"},

		// Genuine Windows 10 must not be relabelled.
		{"Windows 10 Pro", "19045", "Windows 10 Pro"},
		{"Windows 10 Home", "21999", "Windows 10 Home"},

		// Server builds share the high build numbers but not the product name,
		// so the prefix guard must hold.
		{"Windows Server 2022 Standard", "20348", "Windows Server 2022 Standard"},
		{"Windows Server 2025 Datacenter", "26100", "Windows Server 2025 Datacenter"},

		// Unreadable build must leave the name untouched rather than guess.
		{"Windows 10 Pro", "", "Windows 10 Pro"},
		{"Windows 10 Pro", "not-a-number", "Windows 10 Pro"},
	}
	for _, c := range cases {
		if got := normalizeProductName(c.product, c.build); got != c.want {
			t.Errorf("normalizeProductName(%q, %q) = %q, want %q",
				c.product, c.build, got, c.want)
		}
	}
}

func TestBuildNumber(t *testing.T) {
	cases := []struct {
		in   string
		want int
	}{
		{"26200", 26200},
		{"19045", 19045},
		{"", 0},
		{"22H2", 0},    // version strings are not build numbers
		{"26200.1", 0}, // dotted builds must not silently truncate
		{"-1", 0},
	}
	for _, c := range cases {
		if got := buildNumber(c.in); got != c.want {
			t.Errorf("buildNumber(%q) = %d, want %d", c.in, got, c.want)
		}
	}
}

// Patch currency thresholds decide severity, and an off-by-one here changes
// how a client's report reads.
func TestPatchSeverity(t *testing.T) {
	cases := []struct {
		days    int
		wantSev finding.Severity
		wantBad bool
	}{
		{0, finding.Info, false},
		{1, finding.Info, false},
		{35, finding.Info, false}, // boundary: 35 days is still acceptable
		{36, finding.High, true},  // one day past a monthly cycle
		{90, finding.High, true},  // boundary: still high, not yet critical
		{91, finding.Critical, true},
		{400, finding.Critical, true},
	}
	for _, c := range cases {
		sev, bad := patchSeverity(c.days)
		if sev != c.wantSev || bad != c.wantBad {
			t.Errorf("patchSeverity(%d) = %s/%v, want %s/%v",
				c.days, sev, bad, c.wantSev, c.wantBad)
		}
	}
}

func TestPasswordPolicyProblems(t *testing.T) {
	const forever = timeqForever

	// A compliant policy produces no findings.
	if got := passwordPolicyProblems(12, 10, 90*86400); len(got) != 0 {
		t.Errorf("compliant policy reported problems: %v", got)
	}

	// The state observed on the development machine: no minimum, no history.
	got := passwordPolicyProblems(0, 0, 42*86400)
	if len(got) != 2 {
		t.Fatalf("expected 2 problems for a zeroed policy, got %v", got)
	}

	// Boundary: exactly the minimum is acceptable, one below is not.
	if got := passwordPolicyProblems(8, 5, 86400); len(got) != 0 {
		t.Errorf("policy at exactly the baseline should pass, got %v", got)
	}
	if got := passwordPolicyProblems(7, 5, 86400); len(got) != 1 {
		t.Errorf("length one below baseline should fail, got %v", got)
	}

	// Never-expiring passwords are a distinct problem from a weak length.
	got = passwordPolicyProblems(12, 10, forever)
	if len(got) != 1 {
		t.Fatalf("expected 1 problem for non-expiring passwords, got %v", got)
	}
}

// Saved wireless profiles auto-reconnect, so grading them correctly matters
// long after the network was last used.
func TestClassifyWirelessProfile(t *testing.T) {
	cases := []struct {
		name string
		p    wirelessProfile
		want string
	}{
		// Observed on the development machine.
		{"hotel guest wifi", wirelessProfile{"Radisson_Guest", "open", "none"}, "open"},
		{"open with empty encryption", wirelessProfile{"X", "open", ""}, "open"},

		{"WEP by encryption", wirelessProfile{"X", "open", "WEP"}, "wep"},
		{"WEP by shared-key auth", wirelessProfile{"X", "shared", "WEP"}, "wep"},

		{"WPA personal", wirelessProfile{"X", "WPAPSK", "AES"}, "legacy"},
		{"TKIP encryption", wirelessProfile{"X", "WPA2PSK", "TKIP"}, "legacy"},

		// Modern configurations must not be flagged.
		{"WPA2 enterprise", wirelessProfile{"X", "WPA2", "AES"}, ""},
		{"WPA2 personal AES", wirelessProfile{"X", "WPA2PSK", "AES"}, ""},
		{"WPA3", wirelessProfile{"X", "WPA3SAE", "AES"}, ""},
	}
	for _, c := range cases {
		if got := classify(c.p); got != c.want {
			t.Errorf("%s: classify(%+v) = %q, want %q", c.name, c.p, got, c.want)
		}
	}
}

// Ports come from the IP helper API in network byte order. Getting this wrong
// would misreport every listening service.
func TestNtohs(t *testing.T) {
	cases := []struct {
		in   uint32
		want uint16
	}{
		// Input is the byte-swapped form the API returns: port 22 is 0x0016,
		// which arrives as 0x1600.
		{0x1600, 22},   // SSH
		{0x5000, 80},   // HTTP
		{0xBB01, 443},  // HTTPS  (0x01BB swapped)
		{0x3D0D, 3389}, // RDP    (0x0D3D swapped)
		{0xC501, 453},  // arbitrary
		{0x8500, 133},  // low byte only
	}
	for _, c := range cases {
		if got := ntohs(c.in); got != c.want {
			t.Errorf("ntohs(%#x) = %d, want %d", c.in, got, c.want)
		}
	}
}

func TestIsPublicResolver(t *testing.T) {
	// A public resolver prevents the entity filtering or logging its own DNS.
	if op, ok := isPublicResolver("8.8.8.8"); !ok || op != "Google" {
		t.Errorf("8.8.8.8 should be identified as Google, got %q/%v", op, ok)
	}
	if _, ok := isPublicResolver("1.1.1.1"); !ok {
		t.Error("1.1.1.1 should be identified as public")
	}

	// The resolver observed on the development machine is private and must not
	// be flagged.
	if _, ok := isPublicResolver("10.200.157.1"); ok {
		t.Error("10.200.157.1 is a private resolver and must not be flagged")
	}
	// Near-misses must not match.
	if _, ok := isPublicResolver("8.8.8.9"); ok {
		t.Error("8.8.8.9 is not a known public resolver")
	}
}

func TestJoinList(t *testing.T) {
	cases := []struct {
		in   []string
		want string
	}{
		{nil, ""},
		{[]string{"a"}, "a"},
		{[]string{"a", "b"}, "a and b"},
		{[]string{"a", "b", "c"}, "a, b and c"},
	}
	for _, c := range cases {
		if got := joinList(c.in); got != c.want {
			t.Errorf("joinList(%v) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestItoa(t *testing.T) {
	for _, c := range []struct {
		in   int
		want string
	}{{0, "0"}, {7, "7"}, {42, "42"}, {26200, "26200"}, {-5, "-5"}} {
		if got := itoa(c.in); got != c.want {
			t.Errorf("itoa(%d) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestLower(t *testing.T) {
	// The Office policy tree uses lowercase application names; a wrong case
	// silently reads a non-existent registry key, which would report every
	// application as unprotected.
	for _, c := range []struct{ in, want string }{
		{"Word", "word"}, {"Excel", "excel"}, {"PowerPoint", "powerpoint"},
		{"Outlook", "outlook"}, {"Access", "access"},
	} {
		if got := lower(c.in); got != c.want {
			t.Errorf("lower(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}
