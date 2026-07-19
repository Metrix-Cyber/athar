package framework

import (
	"fmt"
	"sort"
	"strings"
)

// Frameworks are registered rather than hardcoded so a new one is a data file
// plus a mapping, not a code change.
//
// Checks do not cite every framework. They cite ECC, and a cross-framework
// mapping translates. Requiring each check to declare codes for every
// framework would couple sixty checks to every framework ever added, and would
// mean a contributor writing a Windows registry check needs to know the SAMA
// Cyber Security Framework to finish it.

// ID identifies a framework catalogue.
type ID string

const (
	// ECCID is the canonical framework. Checks cite ECC codes natively;
	// everything else is reached by mapping.
	ECCID ID = "ecc"
)

// Info describes a registered framework for selection and listing.
type Info struct {
	ID        ID
	Name      string
	Authority string
	// Canonical marks the framework checks cite directly. Exactly one is.
	Canonical bool
	// Sourced reports whether the control text was parsed from the published
	// document. A framework registered without sourced text can be selected
	// but must not present its control text as authoritative.
	Sourced bool
	Note    string
}

var registry = map[ID]*Catalog{}
var infos = map[ID]Info{}

func register(info Info, c *Catalog) {
	c.ID = info.ID
	c.index()
	registry[info.ID] = c
	infos[info.ID] = info
}

// Get returns a registered framework catalogue.
func Get(id ID) (*Catalog, error) {
	if c, ok := registry[id]; ok {
		return c, nil
	}
	return nil, fmt.Errorf("unknown framework %q; available: %s",
		id, strings.Join(AvailableIDs(), ", "))
}

// MustGet returns a catalogue or panics. Only for the canonical framework,
// whose absence is a build error rather than a runtime condition.
func MustGet(id ID) *Catalog {
	c, err := Get(id)
	if err != nil {
		panic("framework: " + err.Error())
	}
	return c
}

// Available lists registered frameworks, canonical first then alphabetically.
func Available() []Info {
	out := make([]Info, 0, len(infos))
	for _, i := range infos {
		out = append(out, i)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Canonical != out[j].Canonical {
			return out[i].Canonical
		}
		return out[i].ID < out[j].ID
	})
	return out
}

// AvailableIDs lists registered framework identifiers.
func AvailableIDs() []string {
	var out []string
	for _, i := range Available() {
		out = append(out, string(i.ID))
	}
	return out
}

// Describe returns the registration record for a framework.
func Describe(id ID) (Info, bool) {
	i, ok := infos[id]
	return i, ok
}
