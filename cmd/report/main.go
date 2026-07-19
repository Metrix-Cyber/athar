// Command report renders a scanner JSON report as a self-contained HTML file.
//
// This is deliberately a separate binary from the scanner. The scanner produces
// data; how much of that data is shown, and how it is branded, is a product
// decision that must stay changeable without touching the checks.
//
// The output has no external references — no CDN, no fonts, no images — so it
// opens correctly on an air-gapped machine and can be mailed as one file.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"html/template"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/Metrix-Cyber/athar/internal/check"
	"github.com/Metrix-Cyber/athar/internal/finding"
	"github.com/Metrix-Cyber/athar/internal/framework"
)

func main() {
	var (
		in    = flag.String("in", "scan.json", "report file(s) to render, comma-separated. Host scans and tenant assessments can be combined into one report.")
		out   = flag.String("out", "report.html", "HTML output path")
		org   = flag.String("org", "", "organization name shown on the report")
		brand = flag.String("brand", "Metrix Cyber", "issuing organization")
	)
	flag.Parse()

	var (
		sources  []Source
		findings []finding.Finding
	)
	for _, path := range strings.Split(*in, ",") {
		path = strings.TrimSpace(path)
		if path == "" {
			continue
		}
		src, fs, err := load(path)
		if err != nil {
			fatal("%v", err)
		}
		sources = append(sources, src)
		findings = append(findings, fs...)
	}
	if len(sources) == 0 {
		fatal("no input files given")
	}

	page := build(sources, findings, *org, *brand)

	f, err := os.Create(*out)
	if err != nil {
		fatal("creating %s: %v", *out, err)
	}
	defer f.Close()

	if err := tmpl.Execute(f, page); err != nil {
		fatal("rendering: %v", err)
	}
	fmt.Printf("Wrote %s\n", *out)
}

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}

type page struct {
	Org           string
	Brand         string
	Sources       []Source
	Summary       check.Summary
	Framework     string
	Groups        []group
	Score         int
	Assessed      int
	Coverage      string
	Remaining     int
	ApplyTitle    string
	ApplyGuidance string
	Generated     string
	HasFail       bool
	SevOrdered    []sevCount
}

type group struct {
	Code     string
	Name     string
	Domain   string
	Findings []finding.Finding
	Fails    int
	// Level and Reason describe how this subdomain can be evidenced, so the
	// report accounts for the whole framework rather than only the parts a
	// scanner can reach.
	Level  string
	Reason string
}

type sevCount struct {
	Name  string
	Count int
	Class string
}

func build(sources []Source, findings []finding.Finding, org, brand string) page {
	summary := summarize(findings)

	byCode := map[string][]finding.Finding{}
	for _, f := range findings {
		byCode[f.Subdomain] = append(byCode[f.Subdomain], f)
	}

	// Every subdomain in the framework appears, not only those the scan
	// reached. A report that lists only what was examined implies the
	// framework ends there.
	cat := framework.ECC()
	var groups []group
	for _, sd := range cat.Subdomains {
		fs := byCode[sd.Code]
		sort.Slice(fs, func(i, j int) bool {
			// Failures first, then by severity weight, then by ID.
			if (fs[i].Status == finding.Fail) != (fs[j].Status == finding.Fail) {
				return fs[i].Status == finding.Fail
			}
			if w := sevWeight(fs[i].Severity) - sevWeight(fs[j].Severity); w != 0 {
				return w < 0
			}
			return fs[i].CheckID < fs[j].CheckID
		})

		lvl, reason := cat.Coverage(sd.Code)
		g := group{
			Code:     sd.Code,
			Name:     sd.Title,
			Domain:   sd.DomainName,
			Findings: fs,
			Level:    string(lvl),
			Reason:   reason,
		}
		for _, f := range fs {
			if f.Status == finding.Fail {
				g.Fails++
			}
		}
		groups = append(groups, g)
	}
	sort.Slice(groups, func(i, j int) bool {
		return subdomainOrder(groups[i].Code) < subdomainOrder(groups[j].Code)
	})

	// Score counts only conclusive results. Undetermined checks are excluded
	// rather than counted as passes — inflating a score with things we could
	// not see is the fastest way to lose a security-literate reader.
	assessed := summary.Pass + summary.Fail
	score := 0
	if assessed > 0 {
		score = summary.Pass * 100 / assessed
	}

	var sevs []sevCount
	for _, s := range []struct{ key, class string }{
		{"critical", "crit"}, {"high", "high"}, {"medium", "med"}, {"low", "low"},
	} {
		if n := summary.BySeverity[s.key]; n > 0 {
			sevs = append(sevs, sevCount{Name: strings.Title(s.key), Count: n, Class: s.class})
		}
	}

	// Remediation guidance is host-specific, so it only appears when a host
	// was assessed. A tenant-only report has no management mode to advise on.
	var applyTitle, applyText string
	for _, src := range sources {
		if src.Kind == "host" && src.Management != nil {
			applyTitle, applyText = applyGuidance(*src.Management)
			break
		}
	}

	generated := time.Now().UTC()
	for _, src := range sources {
		if src.When.After(generated) || generated.IsZero() {
			generated = src.When
		}
	}

	return page{
		Org:           org,
		Brand:         brand,
		Sources:       sources,
		Summary:       summary,
		Framework:     "NCA ECC-2:2024",
		Groups:        groups,
		Score:         score,
		Assessed:      assessed,
		Coverage:      fmt.Sprintf("%d of %d", len(summary.SubdomainsCovered), cat.TotalSubdomains()),
		Remaining:     cat.TotalSubdomains() - len(summary.SubdomainsCovered),
		ApplyTitle:    applyTitle,
		ApplyGuidance: applyText,
		Generated:     generated.Format("2 January 2006, 15:04 MST"),
		HasFail:       summary.Fail > 0,
		SevOrdered:    sevs,
	}
}

// applyGuidance explains how the hardening settings in this report can be
// applied, given how the host is actually administered.
//
// Nearly every setting below lives under HKLM\SOFTWARE\Policies. Group Policy
// is the most familiar writer of those keys but not the only one, and an
// organisation without Active Directory needs to know which mechanism applies
// to them — otherwise the remediation advice is unusable.
func applyGuidance(m check.Management) (string, string) {
	switch m.Mode {
	case "domain":
		return "Active Directory Group Policy",
			"This host is joined to the " + m.Domain + " domain. Apply the settings in this " +
				"report through Group Policy Objects linked to the organisational unit " +
				"containing these devices. Export the resulting GPO reports as evidence of " +
				"implementation for assessment."

	case "mdm":
		return "Mobile device management",
			"This host is enrolled in mobile device management (" + join(m.MDMProviders) + "). " +
				"Apply these settings through configuration profiles using the Policy CSP, " +
				"which writes the same underlying policy values that Group Policy would. " +
				"Active Directory is not required. Export the profile definitions and " +
				"compliance status from the management console as evidence."

	case "local-policy":
		return "Local policy or endpoint management",
			"This host is not domain joined and not enrolled in device management. The " +
				"settings can be applied locally through the Local Group Policy Editor " +
				"(gpedit.msc), or centrally through an endpoint management product, " +
				"configuration-as-code tooling, or a signed PowerShell baseline script. " +
				"Where configuration is applied per device rather than centrally, the " +
				"entity should evidence a documented baseline and a means of detecting drift."

	default:
		return "Scripted baseline required",
			"This host runs a Windows edition without the Local Group Policy Editor and is " +
				"neither domain joined nor enrolled in device management. Settings must be " +
				"applied by writing the underlying policy values directly — through a " +
				"documented and version-controlled configuration script, or by adopting an " +
				"endpoint management product. For an organisation with no directory service, " +
				"a lightweight MDM is usually the least effort route to both applying and " +
				"evidencing these controls."
	}
}

func join(items []string) string {
	out := ""
	for i, s := range items {
		if i > 0 {
			out += ", "
		}
		out += s
	}
	return out
}

// subdomainOrder sorts "2-10" after "2-9" rather than lexically before it.
func subdomainOrder(code string) int {
	var d, s int
	fmt.Sscanf(code, "%d-%d", &d, &s)
	return d*100 + s
}

func sevWeight(s finding.Severity) int {
	switch s {
	case finding.Critical:
		return 0
	case finding.High:
		return 1
	case finding.Medium:
		return 2
	case finding.Low:
		return 3
	}
	return 4
}

var tmpl = template.Must(template.New("report").Funcs(template.FuncMap{
	"sevClass": func(s finding.Severity) string {
		switch s {
		case finding.Critical:
			return "crit"
		case finding.High:
			return "high"
		case finding.Medium:
			return "med"
		case finding.Low:
			return "low"
		}
		return "info"
	},
	"evidence": func(m map[string]any) string {
		if len(m) == 0 {
			return ""
		}
		b, err := json.MarshalIndent(m, "", "  ")
		if err != nil {
			return ""
		}
		return string(b)
	},
}).Parse(htmlTemplate))
