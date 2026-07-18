//go:build windows

package windows

import (
	"context"
	"fmt"
	"sort"

	"golang.org/x/sys/windows/registry"

	"github.com/Metrix-Cyber/athar/internal/check"
	"github.com/Metrix-Cyber/athar/internal/finding"
)

// ECC 2-4 covers email protection. Office macro policy sits here because
// macro-enabled attachments remain the dominant delivery route for malware
// reaching users by email.
var emailCodes = []string{"2-4-2"}

func init() {
	check.Register(check.Check{
		ID: "win.email.office_macros", Subdomain: "2-4", ControlCodes: emailCodes,
		Platforms: []string{"windows"}, Run: officeMacros,
	})
}

// officeApps are the applications whose macro settings matter, keyed by the
// registry path segment used under the Office policy tree.
var officeApps = []string{"Word", "Excel", "PowerPoint", "Outlook", "Access"}

// officeVersions maps the Office version numbers still in use to a label.
var officeVersions = map[string]string{
	"16.0": "Office 2016/2019/365",
	"15.0": "Office 2013",
	"14.0": "Office 2010",
}

// officeMacros checks whether macros from the internet are blocked.
//
// The setting that matters is blockcontentexecutionfrominternet, which stops
// macros in files carrying the internet mark-of-the-web from running at all.
// The older "VBAWarnings" value only controls prompting, and a user who can
// click through a prompt is not protected by it.
func officeMacros(ctx context.Context) []finding.Finding {
	f := finding.New("win.email.office_macros", "Office macro execution policy", "2-4", emailCodes)

	installed := detectOfficeVersions()
	if len(installed) == 0 {
		return []finding.Finding{f.Inapplicable(
			"Microsoft Office does not appear to be installed on this host.")}
	}
	f = f.With("office_versions_detected", installed)

	// An application is reported once even where several Office versions are
	// installed side by side, otherwise a host with two versions reports
	// "Access, Access" and reads as a defect in the report rather than in the
	// host.
	seen := map[string]bool{}
	var unprotected []string
	for _, ver := range installed {
		for _, app := range officeApps {
			path := fmt.Sprintf(`SOFTWARE\Policies\Microsoft\Office\%s\%s\Security`,
				ver, lower(app))
			blocked, present, err := dwordOr(path, "blockcontentexecutionfrominternet", 0)
			if err != nil {
				continue
			}
			protected := present && blocked == 1
			f = f.With(officeVersions[ver]+" "+app+" blocks internet macros", protected)
			if !protected && !seen[app] {
				seen[app] = true
				unprotected = append(unprotected, app)
			}
		}
	}
	sort.Strings(unprotected)

	if len(unprotected) > 0 {
		return []finding.Finding{f.With("applications_not_blocking_internet_macros", unprotected).
			Failed(finding.High,
				fmt.Sprintf("Macros in files originating from the internet are not blocked by policy in: %s. Macro-enabled attachments are a primary malware delivery route, and a user prompt is not an adequate control because it can be dismissed.",
					joinList(unprotected)),
				"Enable 'Block macros from running in Office files from the Internet' by Group Policy for all Office applications.")}
	}

	return []finding.Finding{f.Passed(
		"Macros in Office files originating from the internet are blocked by policy across all detected applications.")}
}

// detectOfficeVersions returns the Office version keys present on the host.
func detectOfficeVersions() []string {
	var out []string
	for ver := range officeVersions {
		if keyExists(`SOFTWARE\Microsoft\Office\`+ver) ||
			keyExists(`SOFTWARE\WOW6432Node\Microsoft\Office\`+ver) {
			out = append(out, ver)
		}
	}
	sort.Sort(sort.Reverse(sort.StringSlice(out)))
	return out
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

// unusedRegistry keeps the registry import meaningful if the file is trimmed;
// referenced deliberately so the dependency is explicit.
var _ = registry.LOCAL_MACHINE
