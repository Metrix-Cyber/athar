package check

import (
	"context"
	"fmt"
	"runtime/debug"
	"time"

	"github.com/Metrix-Cyber/athar/internal/finding"
)

// Report is the complete output of one scan.
type Report struct {
	SchemaVersion  string            `json:"schema_version"`
	ScannerVersion string            `json:"scanner_version"`
	Framework      string            `json:"framework"`
	Host           HostInfo          `json:"host"`
	StartedAt      time.Time         `json:"started_at"`
	FinishedAt     time.Time         `json:"finished_at"`
	Elevated       bool              `json:"elevated"`
	Findings       []finding.Finding `json:"findings"`
	Summary        Summary           `json:"summary"`
}

// HostInfo identifies the scanned machine.
type HostInfo struct {
	Hostname   string     `json:"hostname"`
	OS         string     `json:"os"`
	Arch       string     `json:"arch"`
	Version    string     `json:"os_version,omitempty"`
	Edition    string     `json:"edition,omitempty"`
	Management Management `json:"management"`
}

// Management describes how the host's configuration is administered.
//
// This drives the remediation guidance in the report. Most hardening settings
// live under HKLM\SOFTWARE\Policies, which is where Group Policy writes — but
// Group Policy is not the only writer, and telling an organisation without
// Active Directory to "apply this by Group Policy" is advice they cannot use.
// Detecting how the host is actually managed lets the report say something
// actionable instead.
type Management struct {
	DomainJoined bool     `json:"domain_joined"`
	CloudJoined  bool     `json:"cloud_joined"`
	Domain       string   `json:"domain,omitempty"`
	MDMProviders []string `json:"mdm_providers,omitempty"`
	// Mode is one of: domain, mdm, local-policy, standalone.
	Mode string `json:"mode"`
}

// Summary aggregates findings for the report header.
type Summary struct {
	Total         int            `json:"total"`
	Pass          int            `json:"pass"`
	Fail          int            `json:"fail"`
	Unknown       int            `json:"unknown"`
	NotApplicable int            `json:"not_applicable"`
	BySeverity    map[string]int `json:"by_severity"`
	// SubdomainsCovered lists ECC subdomains this scan produced evidence for.
	// Reporting coverage honestly is a product requirement: the gap between
	// what was checked and the full framework is the services conversation.
	SubdomainsCovered []string `json:"subdomains_covered"`
	// ClausesCited and ClausesTotal give coverage at control-clause level,
	// which is materially lower than subdomain level and is the figure an
	// assessor will compute themselves.
	ClausesCited int `json:"clauses_cited"`
	ClausesTotal int `json:"clauses_total"`
}

// Run executes checks and assembles a report. A panicking check is contained
// and recorded as Unknown rather than killing the scan — one bad check must
// not cost the customer the other fifty-nine.
func Run(ctx context.Context, checks []Check, host HostInfo, elevated bool, version string) Report {
	rep := Report{
		SchemaVersion:  "1.0",
		ScannerVersion: version,
		Framework:      "NCA ECC-2:2024",
		Host:           host,
		StartedAt:      time.Now().UTC(),
		Elevated:       elevated,
	}

	for _, c := range checks {
		rep.Findings = append(rep.Findings, runOne(ctx, c)...)
	}

	rep.FinishedAt = time.Now().UTC()
	rep.Summary = summarize(rep.Findings)

	// Clause coverage counts what the compiled-in checks can cite, not what
	// this particular run happened to reach, so it reflects the scanner's
	// reach rather than one host's configuration.
	cited := map[string]bool{}
	for _, c := range checks {
		for _, code := range c.ControlCodes {
			cited[code] = true
		}
	}
	rep.Summary.ClausesCited = len(cited)

	return rep
}

func runOne(ctx context.Context, c Check) (out []finding.Finding) {
	defer func() {
		if r := recover(); r != nil {
			f := finding.New(c.ID, "Check failed to execute", c.Subdomain, nil)
			out = []finding.Finding{
				f.Undetermined(fmt.Errorf("panic: %v\n%s", r, debug.Stack())),
			}
		}
	}()

	if err := ctx.Err(); err != nil {
		f := finding.New(c.ID, "Check skipped", c.Subdomain, nil)
		return []finding.Finding{f.Undetermined(err)}
	}
	return c.Run(ctx)
}

func summarize(fs []finding.Finding) Summary {
	s := Summary{Total: len(fs), BySeverity: map[string]int{}}
	seen := map[string]bool{}

	for _, f := range fs {
		switch f.Status {
		case finding.Pass:
			s.Pass++
		case finding.Fail:
			s.Fail++
			s.BySeverity[string(f.Severity)]++
		case finding.Unknown:
			s.Unknown++
		case finding.NotApplicable:
			s.NotApplicable++
		}
		if f.Subdomain != "" && !seen[f.Subdomain] {
			seen[f.Subdomain] = true
			s.SubdomainsCovered = append(s.SubdomainsCovered, f.Subdomain)
		}
	}
	return s
}
