package framework

import (
	_ "embed"
	"encoding/json"
)

//go:embed ccc_catalog.json
var cccJSON []byte

// CCCID is the NCA Cloud Cybersecurity Controls.
const CCCID ID = "ccc"

// Audience distinguishes the two control sets the CCC defines.
//
// The CCC is not one list. Every domain splits into requirements on the cloud
// service provider and requirements on the tenant, encoded in the clause
// itself: 2-2-P-1 is the provider's, 2-2-T-1 the tenant's. They are not
// alternatives and not a subset of one another.
//
// This matters commercially as well as technically. A customer running Athar
// is almost always a tenant, and assessing them against provider controls
// would report them non-compliant with requirements that are contractually
// their provider's responsibility — the fastest possible way to lose the
// reader's confidence in the whole report.
type Audience string

const (
	// CSP — obligations on the cloud service provider.
	CSP Audience = "csp"
	// CST — obligations on the cloud service tenant, which is what most
	// organisations running this tool are.
	CST Audience = "cst"
)

func init() {
	var c Catalog
	if err := json.Unmarshal(cccJSON, &c); err != nil {
		panic("framework: malformed embedded CCC catalogue: " + err.Error())
	}
	register(Info{
		ID:        CCCID,
		Name:      "NCA Cloud Cybersecurity Controls (CCC-2:2024)",
		Authority: "National Cybersecurity Authority, Saudi Arabia",
		Canonical: false,
		Sourced:   true,
		Note: "Parsed from the NCA's published document. Extends the ECC for cloud " +
			"services and separates provider (CSP) from tenant (CST) obligations. " +
			"The ECC mapping is read from the document's own cross-references " +
			"(\"In addition to Subcontrols in the ECC control X...\"), so each link " +
			"is the NCA's statement rather than an inference.",
	}, &c)
}

// CCC returns the Cloud Cybersecurity Controls catalogue.
func CCC() *Catalog { return MustGet(CCCID) }

// ControlsFor returns the clauses applying to one audience.
//
// Callers must choose. There is no combined view, because a report that merged
// provider and tenant obligations would misstate what the reader is
// accountable for.
func (c *Catalog) ControlsFor(a Audience) []Control {
	var out []Control
	for _, ctrl := range c.Controls {
		if ctrl.Audience == string(a) {
			out = append(out, ctrl)
		}
	}
	return out
}

//go:embed ccc_mapping.json
var cccMappingJSON []byte

// mappingFile is the on-disk form produced by map_ccc.py.
type mappingFile struct {
	FromFramework string `json:"from_framework"`
	ToFramework   string `json:"to_framework"`
	Note          string `json:"note"`
	Links         []struct {
		From     string `json:"from"`
		To       string `json:"to"`
		Audience string `json:"audience"`
	} `json:"links"`
}

func init() {
	var mf mappingFile
	if err := json.Unmarshal(cccMappingJSON, &mf); err != nil {
		panic("framework: malformed embedded CCC mapping: " + err.Error())
	}

	m := &Mapping{Target: CCCID}
	for _, l := range mf.Links {
		// Every link is the NCA's own statement that a CCC clause extends an
		// ECC clause. "In addition to" is the document's wording, and it means
		// the CCC clause asks for more — so evidence for the ECC clause
		// supports the CCC one without discharging it. That is Supporting, not
		// Exact, and the distinction is the difference between a report that
		// helps an assessor and one that misleads them.
		m.Links = append(m.Links, Link{
			From:       l.From,
			To:         l.To,
			Confidence: Supporting,
			Note: "The CCC states this clause applies in addition to ECC " + l.From +
				". Evidence for the ECC clause supports it but does not discharge it.",
		})
	}
	registerMapping(m)
}
