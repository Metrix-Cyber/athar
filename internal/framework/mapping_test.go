package framework

import "testing"

func TestCCCMappingIsRegistered(t *testing.T) {
	m, ok := MappingTo(CCCID)
	if !ok {
		t.Fatal("no mapping registered for CCC; the framework would not be selectable")
	}
	if len(m.Links) == 0 {
		t.Fatal("CCC mapping is empty")
	}
}

// The CCC extends ECC controls while checks cite the subcontrols beneath them.
// Exact-only matching produced zero coverage against a 171-clause framework,
// which reads as "nothing applies" rather than "the mapping never connected".
func TestTranslateWalksUpToParentControl(t *testing.T) {
	m, _ := MappingTo(CCCID)

	// The document maps ECC 2-2-3. A check citing 2-2-3-1 is evidence toward
	// its parent and must reach the same CCC clauses.
	direct, _ := m.Translate([]string{"2-2-3"})
	viaChild, _ := m.Translate([]string{"2-2-3-1"})

	if len(direct) == 0 {
		t.Fatal("ECC 2-2-3 has no links; the mapping did not load as expected")
	}
	if len(viaChild) != len(direct) {
		t.Errorf("subcontrol 2-2-3-1 reached %d clauses, parent 2-2-3 reached %d; a child must inherit its parent's links",
			len(viaChild), len(direct))
	}
}

func TestTranslateDoesNotWalkBelowAControl(t *testing.T) {
	// Walking down to a subdomain would attach findings across an entire
	// section on the strength of one check.
	m, _ := MappingTo(CCCID)
	if links, _ := m.Translate([]string{"2-2"}); len(links) != 0 {
		t.Errorf("a bare subdomain code resolved to %d links; it should resolve to none", len(links))
	}
}

func TestTranslateReportsUnmappedRatherThanDropping(t *testing.T) {
	// A finding that maps nowhere still happened. Dropping it silently would
	// misrepresent both the scan and the framework's coverage.
	m, _ := MappingTo(CCCID)
	_, unmapped := m.Translate([]string{"9-9-9"})
	if len(unmapped) != 1 || unmapped[0] != "9-9-9" {
		t.Errorf("unmapped = %v, want the unmatched code returned", unmapped)
	}
}

func TestCCCLinksResolveToRealClauses(t *testing.T) {
	// A link pointing at a clause that does not exist in the target catalogue
	// would put a finding under a control no one can look up.
	m, _ := MappingTo(CCCID)
	ccc := CCC()
	ecc := ECC()

	var badTarget, badSource []string
	for _, l := range m.Links {
		if _, ok := ccc.Lookup(l.To); !ok {
			badTarget = append(badTarget, l.To)
		}
		// A source may be a control or a subdomain. The CCC document sometimes
		// writes "the ECC control 2-1" where 2-1 is in fact a subdomain — an
		// imprecision in the published text, not in the extraction. Accepting
		// it reflects what the document says; rejecting it would discard a
		// real correspondence because the authority worded it loosely.
		if _, ok := ecc.Lookup(l.From); !ok && ecc.SubdomainTitle(l.From) == "" {
			badSource = append(badSource, l.From)
		}
	}
	if len(badTarget) > 0 {
		t.Errorf("%d links point at CCC clauses not in the catalogue, e.g. %v",
			len(badTarget), badTarget[:min(3, len(badTarget))])
	}
	if len(badSource) > 0 {
		t.Errorf("%d links come from ECC clauses not in the catalogue, e.g. %v",
			len(badSource), badSource[:min(3, len(badSource))])
	}
}

func TestCCCLinksStayWithinOneTargetSubdomain(t *testing.T) {
	// Each cross-reference in the document introduces one section's clauses.
	// An ECC clause reaching several CCC subdomains means the extractor let
	// the next section bleed in — the defect that made the first attempt
	// untrustworthy.
	m, _ := MappingTo(CCCID)

	subs := map[string]map[string]bool{}
	for _, l := range m.Links {
		parts := l.To
		sub := parts[:3] // "2-2-P-1-1" -> "2-2"
		if subs[l.From] == nil {
			subs[l.From] = map[string]bool{}
		}
		subs[l.From][sub] = true
	}
	for from, s := range subs {
		if len(s) > 1 {
			t.Errorf("ECC %s maps into %d CCC subdomains; section bleed has returned", from, len(s))
		}
	}
}

func TestCCCLinksAreSupportingNotExact(t *testing.T) {
	// The document's wording is "in addition to", meaning the CCC clause asks
	// for more than the ECC one. Presenting that as an exact correspondence
	// would tell an assessor a control is discharged when it is not.
	m, _ := MappingTo(CCCID)
	for _, l := range m.Links {
		if l.Confidence != Supporting {
			t.Errorf("link %s -> %s has confidence %q; CCC extends ECC and cannot be exact",
				l.From, l.To, l.Confidence)
			break
		}
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
