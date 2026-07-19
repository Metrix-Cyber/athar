// Package report renders Athar scan and tenant assessment output as a
// self-contained HTML document.
//
// It lives in its own package so both the standalone report command and the
// scanner's guided mode can render without either shelling out to the other —
// the scanner guarantees it executes no subprocesses, and that guarantee is
// worth more than the convenience of calling a second binary.
package report

import (
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/Metrix-Cyber/athar/internal/check"
	"github.com/Metrix-Cyber/athar/internal/finding"
	"github.com/Metrix-Cyber/athar/internal/framework"
)

// Render writes an HTML report for the given sources and findings, structured
// against the selected framework.
func Render(w io.Writer, target framework.ID, sources []Source, findings []finding.Finding, org, brand string) error {
	pg, err := build(target, sources, findings, org, brand)
	if err != nil {
		return err
	}
	return tmpl.Execute(w, pg)
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
	Digest        string
	CatalogueVer  string
	Unmapped      []finding.Finding
	HasFail       bool
	SevOrdered    []sevCount
}

// shown pairs a finding with the clause codes to display for it. In a report
// against a non-canonical framework those are the target framework's clauses,
// not the ECC codes the check cites — a reader assessing against the CCC needs
// CCC clause numbers, and showing ECC codes under CCC headings reads as a
// mistake.
type shown struct {
	finding.Finding
	Codes     []string
	Framework string
	// MappingNote explains the correspondence for mapped clauses, so a reader
	// can judge the link rather than take it on trust.
	MappingNote string
}

type group struct {
	Code     string
	Name     string
	Domain   string
	Findings []shown
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

func build(target framework.ID, sources []Source, findings []finding.Finding, org, brand string) (page, error) {
	summary := summarize(findings)

	view, err := BuildView(target, findings)
	if err != nil {
		return page{}, err
	}
	cat := view.Catalog

	// Group findings by the *selected* framework's subdomains. For the
	// canonical framework a finding's own subdomain is the right key; for any
	// other, findings arrive via the mapping and their ECC subdomain means
	// nothing in the target's numbering.
	byCode := map[string][]shown{}
	if target == framework.ECCID {
		for _, f := range findings {
			byCode[f.Subdomain] = append(byCode[f.Subdomain], shown{
				Finding: f, Codes: f.ControlCodes, Framework: cat.Framework,
			})
		}
	} else {
		// Collect the target clauses each check reaches, per subdomain, so a
		// check appears once with all the clauses it evidences rather than
		// repeated per clause.
		codes := map[string]map[string][]string{}
		byID := map[string]finding.Finding{}
		for clause, fs := range view.Mapped {
			sub := clauseSubdomain(clause)
			if codes[sub] == nil {
				codes[sub] = map[string][]string{}
			}
			for _, f := range fs {
				codes[sub][f.CheckID] = append(codes[sub][f.CheckID], clause)
				byID[f.CheckID] = f
			}
		}
		for sub, perCheck := range codes {
			for id, clauses := range perCheck {
				sort.Strings(clauses)
				byCode[sub] = append(byCode[sub], shown{
					Finding:   byID[id],
					Codes:     clauses,
					Framework: cat.Framework,
					MappingNote: "The " + cat.Framework + " states these clauses apply in addition to " +
						"the ECC clauses this check evidences, so this finding supports them without discharging them.",
				})
			}
		}
	}

	// Every subdomain in the framework appears, not only those the scan
	// reached. A report that lists only what was examined implies the
	// framework ends there.
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
		if target != framework.ECCID {
			// Coverage classifications describe the ECC's subdomains. Applying
			// them to another framework's numbering would attach the wrong
			// rationale to the wrong control.
			lvl, reason = "", ""
			if len(fs) == 0 {
				reason = "No host or tenant check reaches this subdomain. It must be assessed by other means."
			}
		}
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
		Framework:     cat.Framework,
		Groups:        groups,
		Score:         score,
		Assessed:      assessed,
		Coverage:      fmt.Sprintf("%d of %d", len(summary.SubdomainsCovered), cat.TotalSubdomains()),
		Remaining:     cat.TotalSubdomains() - len(summary.SubdomainsCovered),
		ApplyTitle:    applyTitle,
		ApplyGuidance: applyText,
		Generated:     generated.Format("2 January 2006, 15:04 MST"),
		Digest:        finding.Digest(findings),
		CatalogueVer:  cat.Framework,
		Unmapped:      view.Unmapped,
		HasFail:       summary.Fail > 0,
		SevOrdered:    sevs,
	}, nil
}

// clauseSubdomain extracts the subdomain from a clause code, handling both
// ECC-style "2-2-3-1" and CCC-style "2-2-P-1-1".
func clauseSubdomain(code string) string {
	parts := strings.SplitN(code, "-", 3)
	if len(parts) < 2 {
		return code
	}
	return parts[0] + "-" + parts[1]
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
