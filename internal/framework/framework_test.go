package framework

import (
	"strings"
	"testing"
)

// Validate is the gate that stops a check citing a control which does not
// exist from reaching a customer's report. It is the most consequential piece
// of pure logic in the project and had no test.

func TestValidateRejectsUnknownControl(t *testing.T) {
	err := ECC().Validate(map[string][]string{
		"good.check": {"2-2-2"},
		"bad.check":  {"2-2-9-9"},
	})
	if err == nil {
		t.Fatal("validation passed a control code that does not exist")
	}
	if !strings.Contains(err.Error(), "bad.check") {
		t.Errorf("error must name the offending check, got: %v", err)
	}
	if !strings.Contains(err.Error(), "2-2-9-9") {
		t.Errorf("error must name the offending code, got: %v", err)
	}
}

func TestValidateAcceptsRealControls(t *testing.T) {
	// Codes taken from the shipped catalogue across all four domains.
	err := ECC().Validate(map[string][]string{
		"a": {"1-1-1"},
		"b": {"2-2-3-1", "2-2-3-5"},
		"c": {"3-1-1"},
		"d": {"4-2-1"},
	})
	if err != nil {
		t.Errorf("validation rejected real control codes: %v", err)
	}
}

func TestValidateRejectsCheckCitingNothing(t *testing.T) {
	// A check with no control mapping produces findings an assessor cannot
	// place in the framework, which makes them unusable as evidence.
	if err := ECC().Validate(map[string][]string{"orphan": {}}); err == nil {
		t.Error("a check citing no control should fail validation")
	}
}

func TestEmbeddedCatalogueMatchesPublishedCounts(t *testing.T) {
	// The NCA document states 4 domains, 28 subdomains, 108 controls and 92
	// subcontrols. A parser regression that silently dropped entries would
	// otherwise show up only as quietly reduced coverage.
	c := ECC()

	if got := len(c.Domains); got != 4 {
		t.Errorf("domains = %d, want 4", got)
	}
	if got := c.TotalSubdomains(); got != 28 {
		t.Errorf("subdomains = %d, want 28", got)
	}

	var controls, subcontrols int
	for _, ctrl := range c.Controls {
		switch ctrl.Kind {
		case KindControl:
			controls++
		case KindSubcontrol:
			subcontrols++
		}
	}
	if controls != 108 {
		t.Errorf("controls = %d, want 108", controls)
	}
	// 91 of 92: one subcontrol could not be located in the source PDF. This is
	// asserted rather than glossed so that the shortfall stays visible, and so
	// that recovering it shows up as a deliberate test change.
	if subcontrols != 91 {
		t.Errorf("subcontrols = %d, want 91 (92 published, one not recovered from the PDF)",
			subcontrols)
	}
}

func TestCatalogueFlagsUnverifiedEntries(t *testing.T) {
	// Entries whose text could not be cleanly extracted must stay marked, so
	// unverified regulatory text is never presented as authoritative.
	review := ECC().ReviewNeeded()
	if len(review) == 0 {
		t.Fatal("no entries flagged for review; the flag has been lost")
	}
	for _, c := range review {
		if !c.NeedsReview {
			t.Errorf("%s returned by ReviewNeeded but not marked", c.Code)
		}
	}
}

func TestLookupResolvesControls(t *testing.T) {
	c := ECC()

	ctrl, ok := c.Lookup("2-2-3-1")
	if !ok {
		t.Fatal("2-2-3-1 not found in the catalogue")
	}
	if ctrl.Subdomain != "2-2" {
		t.Errorf("subdomain = %q, want 2-2", ctrl.Subdomain)
	}
	if ctrl.Kind != KindSubcontrol {
		t.Errorf("kind = %q, want subcontrol", ctrl.Kind)
	}
	// The parent must be derivable, since findings group by it.
	if ctrl.Parent != "2-2-3" {
		t.Errorf("parent = %q, want 2-2-3", ctrl.Parent)
	}

	if _, ok := c.Lookup("9-9-9"); ok {
		t.Error("a nonexistent code resolved")
	}
}

func TestSubdomainTitles(t *testing.T) {
	c := ECC()
	if got := c.SubdomainTitle("2-2"); !strings.Contains(got, "Identity") {
		t.Errorf("2-2 title = %q, expected it to mention Identity", got)
	}
	if got := c.SubdomainTitle("9-9"); got != "" {
		t.Errorf("unknown subdomain returned %q, want empty", got)
	}
}

func TestClauseCoverageCountsDistinctValidCodes(t *testing.T) {
	cited, total := ECC().ClauseCoverage(map[string][]string{
		"a": {"2-2-2", "2-2-3-1"},
		"b": {"2-2-2"},   // duplicate, must count once
		"c": {"9-9-9-9"}, // invalid, must not count
	})
	if cited != 2 {
		t.Errorf("cited = %d, want 2 distinct valid codes", cited)
	}
	if total != len(ECC().Controls) {
		t.Errorf("total = %d, want the full clause count %d", total, len(ECC().Controls))
	}
}

func TestEverySubdomainHasCoverageClassification(t *testing.T) {
	// The report states an assessment method for all 28 subdomains. A missing
	// classification would silently fall back to "assessor", overstating what
	// requires human judgement and understating what a scan could reach.
	c := ECC()
	for _, s := range c.Subdomains {
		lvl, reason := c.Coverage(s.Code)
		if reason == "" || strings.Contains(reason, "not classified") {
			t.Errorf("%s (%s) has no coverage rationale", s.Code, s.Title)
		}
		switch lvl {
		case Automated, Documentary, Assessor, Partial:
		default:
			t.Errorf("%s has unrecognised assessability %q", s.Code, lvl)
		}
	}
}

func TestCoverageSummaryTotalsAllSubdomains(t *testing.T) {
	c := ECC()
	sum := c.CoverageSummary()

	var total int
	for _, n := range sum {
		total += n
	}
	if total != c.TotalSubdomains() {
		t.Errorf("coverage summary totals %d, want %d subdomains", total, c.TotalSubdomains())
	}
}
