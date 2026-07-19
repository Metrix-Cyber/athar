package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/Metrix-Cyber/athar/internal/check"
	"github.com/Metrix-Cyber/athar/internal/finding"
)

// inputReport accepts either a host scan or a tenant assessment.
//
// The two producers emit different shapes — a host scan carries host and
// elevation detail, a tenant assessment carries provider and tenant — so the
// fields are optional and the source type is inferred from which are present.
// Decoding both into one struct keeps the report tool from needing to know
// which tool produced a file before reading it.
type inputReport struct {
	SchemaVersion string    `json:"schema_version"`
	Framework     string    `json:"framework"`
	StartedAt     time.Time `json:"started_at"`
	FinishedAt    time.Time `json:"finished_at"`

	// Host scan fields.
	Host     *check.HostInfo `json:"host"`
	Elevated bool            `json:"elevated"`

	// Tenant assessment fields.
	Provider string `json:"provider"`
	Tenant   string `json:"tenant"`

	Findings []finding.Finding `json:"findings"`
}

// Source describes one assessed thing, for the report header.
type Source struct {
	Kind     string // "host" or "tenant"
	Name     string
	Detail   string
	Elevated bool
	// Partial marks a source that could not be fully assessed, so the report
	// can say so rather than presenting incomplete coverage as complete.
	Partial bool
	When    time.Time
	// Management carries the host's administration mode so the report can give
	// remediation guidance that matches how the host is actually managed.
	// Nil for tenant sources, which have no such concept.
	Management *check.Management
}

// load reads and classifies one report file.
func load(path string) (Source, []finding.Finding, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return Source{}, nil, err
	}

	// Strip a UTF-8 byte order mark. Athar's own tools never write one, but a
	// file that has been through a Windows editor or PowerShell redirection
	// often has one, and the resulting error ("invalid character 'ï'") gives a
	// user no idea what is wrong with their file.
	raw = bytes.TrimPrefix(raw, []byte{0xEF, 0xBB, 0xBF})

	var in inputReport
	if err := json.Unmarshal(raw, &in); err != nil {
		return Source{}, nil, fmt.Errorf("parsing %s: %w", path, err)
	}
	if len(in.Findings) == 0 && in.Host == nil && in.Provider == "" {
		return Source{}, nil, fmt.Errorf(
			"%s does not look like an Athar report: no findings, host or provider present", path)
	}

	s := Source{When: in.FinishedAt}
	switch {
	case in.Provider != "":
		s.Kind = "tenant"
		s.Name = in.Tenant
		s.Detail = providerLabel(in.Provider)
		if s.Name == "" || s.Name == "(unspecified)" {
			s.Name = s.Detail
			s.Detail = ""
		}

	case in.Host != nil:
		s.Kind = "host"
		s.Name = in.Host.Hostname
		s.Detail = fmt.Sprintf("%s %s", in.Host.OS, in.Host.Version)
		if in.Host.Edition != "" {
			s.Detail = fmt.Sprintf("%s %s (%s)", in.Host.OS, in.Host.Version, in.Host.Edition)
		}
		s.Elevated = in.Elevated
		mgmt := in.Host.Management
		s.Management = &mgmt
		// An unelevated host scan leaves checks undetermined, so the source is
		// flagged partial rather than the shortfall being buried in findings.
		s.Partial = !in.Elevated

	default:
		s.Kind = "unknown"
		s.Name = path
	}

	// Undetermined findings mean something could not be read regardless of
	// source type.
	for _, f := range in.Findings {
		if f.Status == finding.Unknown {
			s.Partial = true
			break
		}
	}

	return s, in.Findings, nil
}

func providerLabel(p string) string {
	switch p {
	case "microsoft-365":
		return "Microsoft 365"
	case "google-workspace":
		return "Google Workspace"
	}
	return p
}

// summarize recomputes totals across every source, so a combined report is
// scored as one assessment rather than several.
func summarize(fs []finding.Finding) check.Summary {
	s := check.Summary{Total: len(fs), BySeverity: map[string]int{}}
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
