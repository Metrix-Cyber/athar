package framework

import "sort"

// Cross-framework mapping translates the ECC clauses a check cites into the
// clauses of whichever framework a report is being produced against.
//
// A mapping is an assertion that two clauses ask for materially the same
// thing. That is a judgement, and a wrong one puts a finding under a control
// it does not evidence — which an assessor familiar with the target framework
// will notice immediately. Mappings therefore carry a confidence and a note,
// and the report distinguishes an exact correspondence from a partial one
// rather than presenting every mapping as equivalent.
//
// Deliberately absent: any mapping invented to improve apparent coverage. A
// clause with no genuine counterpart is left unmapped, and the report says the
// framework's control needs assessing another way.

// Confidence grades how closely two clauses correspond.
type Confidence string

const (
	// Exact — the clauses ask for the same thing, and evidence for one is
	// evidence for the other without qualification.
	Exact Confidence = "exact"
	// Supporting — the target clause asks for more than the source clause
	// evidences. The finding is relevant but does not discharge the control
	// on its own.
	//
	// Named Supporting rather than Partial to avoid colliding with the
	// assessability of the same name: they answer different questions, and one
	// identifier meaning both "a scan covers part of this subdomain" and "this
	// mapping is inexact" would be read wrongly at a glance.
	Supporting Confidence = "supporting"
)

// Link is one mapping between a source clause and a target clause.
type Link struct {
	// From is a clause in the canonical framework (ECC).
	From string
	// To is a clause in the target framework.
	To         string
	Confidence Confidence
	// Note records why the correspondence holds, or what the target requires
	// beyond what the source evidences. It is shown in the report for partial
	// links so a reader can judge the mapping rather than trust it.
	Note string
}

// Mapping is a set of links from the canonical framework to one target.
type Mapping struct {
	Target ID
	Links  []Link

	byFrom map[string][]Link
}

var mappings = map[ID]*Mapping{}

func registerMapping(m *Mapping) {
	m.byFrom = map[string][]Link{}
	for _, l := range m.Links {
		m.byFrom[l.From] = append(m.byFrom[l.From], l)
	}
	mappings[m.Target] = m
}

// MappingTo returns the mapping from the canonical framework to a target, and
// whether one exists.
func MappingTo(target ID) (*Mapping, bool) {
	m, ok := mappings[target]
	return m, ok
}

// Translate converts canonical clause codes into target clause codes.
//
// Codes with no link are returned separately rather than dropped: a finding
// that maps to nothing in the selected framework still happened, and hiding it
// would misrepresent both the scan and the framework's coverage.
func (m *Mapping) Translate(codes []string) (mapped []Link, unmapped []string) {
	seen := map[string]bool{}
	for _, code := range codes {
		links, ok := m.byFrom[code]
		if !ok {
			unmapped = append(unmapped, code)
			continue
		}
		for _, l := range links {
			key := l.From + "->" + l.To
			if seen[key] {
				continue
			}
			seen[key] = true
			mapped = append(mapped, l)
		}
	}
	sort.Slice(mapped, func(i, j int) bool { return mapped[i].To < mapped[j].To })
	sort.Strings(unmapped)
	return mapped, unmapped
}

// TargetsCovered lists the distinct target clauses reachable from a set of
// canonical codes. Used to report coverage against the selected framework
// rather than against ECC.
func (m *Mapping) TargetsCovered(codes []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, code := range codes {
		for _, l := range m.byFrom[code] {
			if !seen[l.To] {
				seen[l.To] = true
				out = append(out, l.To)
			}
		}
	}
	sort.Strings(out)
	return out
}
