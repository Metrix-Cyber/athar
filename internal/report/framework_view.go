package report

import (
	"fmt"

	"github.com/Metrix-Cyber/athar/internal/finding"
	"github.com/Metrix-Cyber/athar/internal/framework"
)

// A scan is framework-agnostic: it reads host state and cites ECC, the
// canonical framework. Selecting a different framework is therefore a
// reporting concern, not a scanning one — the same scan can be presented
// against whichever framework the reader is accountable to, without rerunning
// anything on the host.

// View is a report structured against one framework.
type View struct {
	Catalog *framework.Catalog
	Info    framework.Info

	// Mapped groups findings by the selected framework's clause codes.
	Mapped map[string][]finding.Finding
	// Unmapped are findings whose ECC clauses have no counterpart in the
	// selected framework. They are kept rather than dropped: the check still
	// ran and still found something, and silently discarding it would
	// misrepresent both the scan and the framework.
	Unmapped []finding.Finding
	// Uncovered are clauses of the selected framework that no finding reaches.
	Uncovered []framework.Control
}

// BuildView presents findings against the selected framework.
//
// Selecting the canonical framework is the identity case and needs no mapping.
// Any other framework requires one, and its absence is an error rather than an
// empty report — a report showing zero findings against CCC would read as "no
// problems found" when it means "no translation exists".
func BuildView(target framework.ID, findings []finding.Finding) (*View, error) {
	cat, err := framework.Get(target)
	if err != nil {
		return nil, err
	}
	info, _ := framework.Describe(target)

	v := &View{
		Catalog: cat,
		Info:    info,
		Mapped:  map[string][]finding.Finding{},
	}

	if target == framework.ECCID {
		for _, f := range findings {
			for _, code := range f.ControlCodes {
				v.Mapped[code] = append(v.Mapped[code], f)
			}
		}
		v.Uncovered = uncovered(cat, v.Mapped, "")
		return v, nil
	}

	mapping, ok := framework.MappingTo(target)
	if !ok {
		return nil, fmt.Errorf(
			"no verified mapping from the canonical framework to %s.\n\n"+
				"Checks cite %s clauses, so presenting them against %s requires a "+
				"clause-to-clause mapping. Producing a report without one would show "+
				"no findings, which a reader would take to mean no problems were "+
				"found rather than that no translation exists.",
			info.Name, framework.ECCID, target)
	}

	for _, f := range findings {
		links, unmapped := mapping.Translate(f.ControlCodes)
		if len(links) == 0 {
			v.Unmapped = append(v.Unmapped, f)
			continue
		}
		_ = unmapped
		for _, l := range links {
			v.Mapped[l.To] = append(v.Mapped[l.To], f)
		}
	}

	v.Uncovered = uncovered(cat, v.Mapped, "")
	return v, nil
}

// uncovered lists clauses no finding reaches, optionally limited to one
// audience where a framework splits obligations between parties.
func uncovered(cat *framework.Catalog, mapped map[string][]finding.Finding, audience string) []framework.Control {
	var out []framework.Control
	for _, c := range cat.Controls {
		if audience != "" && c.Audience != audience {
			continue
		}
		if len(mapped[c.Code]) == 0 {
			out = append(out, c)
		}
	}
	return out
}

// Coverage reports how many of the selected framework's clauses are reached.
func (v *View) Coverage() (reached, total int) {
	return len(v.Mapped), len(v.Catalog.Controls)
}
