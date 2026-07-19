// Package framework provides the compliance control catalogue.
//
// The catalogue is parsed from the NCA's published ECC-2:2024 PDF by
// parse_ecc.py and embedded here. Checks reference controls by code; this
// package is what makes those references verifiable rather than assumed.
//
// Adding another framework later (SAMA CSF, PDPL) means adding another
// catalogue file and cross-mapping table — not changing any check.
package framework

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

//go:embed ecc_catalog.json
var eccJSON []byte

// Kind distinguishes a control from one of its subcontrols.
type Kind string

const (
	KindControl    Kind = "control"
	KindSubcontrol Kind = "subcontrol"
)

// Control is one clause of the framework.
type Control struct {
	Code      string `json:"code"`
	Subdomain string `json:"subdomain"`
	Parent    string `json:"parent,omitempty"`
	Kind      Kind   `json:"kind"`
	Text      string `json:"text"`
	// Audience is set by frameworks that split obligations between parties,
	// such as the CCC's provider and tenant control sets. Empty where the
	// framework makes no such distinction.
	Audience string `json:"audience,omitempty"`
	// NeedsReview marks entries whose text could not be cleanly recovered from
	// the source PDF and must be verified by a human against the official
	// document before this catalogue is treated as authoritative.
	NeedsReview bool `json:"needs_review,omitempty"`
}

// Subdomain groups controls, e.g. "2-2 Identity and Access Management".
type Subdomain struct {
	Code       string `json:"code"`
	Domain     string `json:"domain"`
	DomainName string `json:"domain_name"`
	Title      string `json:"title"`
}

// Catalog is a complete framework definition.
type Catalog struct {
	// ID is the registry identifier, set on registration.
	ID         ID          `json:"-"`
	Framework  string      `json:"framework"`
	Source     string      `json:"source"`
	Domains    []Domain    `json:"domains"`
	Subdomains []Subdomain `json:"subdomains"`
	Controls   []Control   `json:"controls"`

	byCode      map[string]Control
	bySubdomain map[string]Subdomain
}

// Domain is a top-level framework grouping.
type Domain struct {
	Code string `json:"code"`
	Name string `json:"name"`
}

func init() {
	var c Catalog
	if err := json.Unmarshal(eccJSON, &c); err != nil {
		panic("framework: malformed embedded ECC catalogue: " + err.Error())
	}
	register(Info{
		ID:        ECCID,
		Name:      "NCA Essential Cybersecurity Controls (ECC-2:2024)",
		Authority: "National Cybersecurity Authority, Saudi Arabia",
		Canonical: true,
		Sourced:   true,
		Note:      "Parsed from the NCA's published document. Six entries are flagged for verification where the source text could not be cleanly extracted.",
	}, &c)
}

// ECC returns the canonical framework. Checks cite its clauses directly.
func ECC() *Catalog { return MustGet(ECCID) }

func (c *Catalog) index() {
	c.byCode = make(map[string]Control, len(c.Controls))
	for _, ctrl := range c.Controls {
		c.byCode[ctrl.Code] = ctrl
	}
	c.bySubdomain = make(map[string]Subdomain, len(c.Subdomains))
	for _, s := range c.Subdomains {
		c.bySubdomain[s.Code] = s
	}
}

// Lookup returns the control with the given code.
func (c *Catalog) Lookup(code string) (Control, bool) {
	ctrl, ok := c.byCode[code]
	return ctrl, ok
}

// SubdomainTitle returns the human-readable title for a subdomain code.
func (c *Catalog) SubdomainTitle(code string) string {
	if s, ok := c.bySubdomain[code]; ok {
		return s.Title
	}
	return ""
}

// TotalSubdomains reports how many subdomains the framework defines, so
// coverage can be stated as a fraction of the real framework rather than of
// whatever the scanner happens to implement.
func (c *Catalog) TotalSubdomains() int { return len(c.Subdomains) }

// Validate checks that every referenced control code exists in the catalogue.
//
// This is the guard against the most damaging class of error in a compliance
// product: a finding that cites a control code which does not exist, or cites
// one that says something different from what the check actually verified. It
// runs at startup so a bad mapping fails loudly in development rather than
// quietly in a customer's report.
func (c *Catalog) Validate(refs map[string][]string) error {
	var problems []string
	for checkID, codes := range refs {
		if len(codes) == 0 {
			problems = append(problems, fmt.Sprintf("%s references no control", checkID))
			continue
		}
		for _, code := range codes {
			if _, ok := c.byCode[code]; !ok {
				problems = append(problems,
					fmt.Sprintf("%s references unknown control %q", checkID, code))
			}
		}
	}
	if len(problems) == 0 {
		return nil
	}
	sort.Strings(problems)
	return fmt.Errorf("catalogue validation failed:\n  %s", strings.Join(problems, "\n  "))
}

// ClauseCoverage reports how many control clauses the given check references
// cite, out of the framework's total.
//
// Subdomain-level coverage flatters the position: a subdomain counts as
// covered when a single check touches it, even where it contains eight clauses
// and one is evidenced. An assessor will work the clause figure out
// regardless, so the report states it rather than waiting to be asked.
func (c *Catalog) ClauseCoverage(refs map[string][]string) (cited, total int) {
	valid := map[string]bool{}
	for _, codes := range refs {
		for _, code := range codes {
			if _, ok := c.byCode[code]; ok {
				valid[code] = true
			}
		}
	}
	return len(valid), len(c.Controls)
}

// ReviewNeeded lists controls whose text requires human verification against
// the source document.
func (c *Catalog) ReviewNeeded() []Control {
	var out []Control
	for _, ctrl := range c.Controls {
		if ctrl.NeedsReview {
			out = append(out, ctrl)
		}
	}
	return out
}
