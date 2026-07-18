// Package check defines the check contract and the registry.
//
// Checks register themselves in init(), so adding a check is one new file with
// no edits to a central list. The runner discovers whatever is registered and
// compiled in for the target platform.
package check

import (
	"context"
	"runtime"
	"sort"
	"sync"

	"github.com/Metrix-Cyber/athar/internal/finding"
)

// Func runs one check and returns its findings. A single check may emit
// several findings (e.g. one per volume, one per firewall profile).
//
// A Func must never modify the host and must never make network calls. It
// returns findings rather than errors: an inability to determine an answer is
// itself a reportable outcome, expressed as finding.Unknown.
type Func func(ctx context.Context) []finding.Finding

// Check is a registered check and its metadata.
type Check struct {
	// ID is stable and namespaced: "<platform>.<area>.<name>".
	ID string
	// Subdomain is the ECC-2:2024 subdomain, e.g. "2-2".
	Subdomain string
	// ControlCodes are every control this check can cite. Declared here as
	// well as on individual findings so the whole registry can be validated
	// against the framework catalogue at startup, before any scan runs.
	ControlCodes []string
	// Platforms lists GOOS values this check applies to.
	Platforms []string
	// NeedsAdmin reports whether the check requires elevation to be
	// conclusive. Checks that can degrade gracefully should not set this;
	// they should return Unknown for the parts they cannot see.
	NeedsAdmin bool
	Run        Func
}

var (
	mu       sync.RWMutex
	registry = map[string]Check{}
)

// Register adds a check. It panics on duplicate IDs, which can only be a
// programming error and should fail at startup rather than silently drop a
// check from every scan.
func Register(c Check) {
	mu.Lock()
	defer mu.Unlock()
	if _, dup := registry[c.ID]; dup {
		panic("check: duplicate check ID " + c.ID)
	}
	registry[c.ID] = c
}

// ForCurrentPlatform returns registered checks applicable to this host,
// ordered by ID so scan output is deterministic.
func ForCurrentPlatform() []Check {
	mu.RLock()
	defer mu.RUnlock()

	out := make([]Check, 0, len(registry))
	for _, c := range registry {
		for _, p := range c.Platforms {
			if p == runtime.GOOS {
				out = append(out, c)
				break
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// ControlRefs maps each registered check to the control codes it declares,
// for validation against the framework catalogue.
func ControlRefs() map[string][]string {
	mu.RLock()
	defer mu.RUnlock()

	refs := make(map[string][]string, len(registry))
	for id, c := range registry {
		refs[id] = c.ControlCodes
	}
	return refs
}

// All returns every registered check regardless of platform, ordered by ID.
// Used for catalog listing (--list) and coverage reporting.
func All() []Check {
	mu.RLock()
	defer mu.RUnlock()

	out := make([]Check, 0, len(registry))
	for _, c := range registry {
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}
