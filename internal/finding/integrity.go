package finding

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
)

// Digest computes a stable SHA-256 over a set of findings.
//
// A compliance report travels: scanner to consultant to client to assessor,
// often as an email attachment. Nothing along that path currently detects an
// edit — changing "fail" to "pass" in the JSON, or a number in the HTML, leaves
// no trace. For a document that may end up in front of a regulator, that is a
// real gap, and it is the one ADR-001 flagged as evidence integrity.
//
// This does not prevent tampering, and it is not a signature: anyone who edits
// the findings can recompute the digest. What it gives is a fixed reference
// that can be quoted separately from the document — in an engagement letter, an
// email, or a case record — so a later copy can be checked against what was
// actually produced. Cryptographic signing of evidence belongs in the platform,
// where a key can be held somewhere the customer does not control.
//
// It identifies a report, not a host state. Scan timestamps are excluded so the
// digest depends on findings rather than on when they were produced, but two
// scans of the same machine minutes apart will still differ: ephemeral ports
// open and close, so the listening-services evidence genuinely changes. That
// was measured, not assumed — an earlier version of this comment claimed
// otherwise and was wrong, because the test fixtures were static and never
// challenged it.
//
// Volatile evidence is deliberately not excluded to force stability. Excluding
// fields to make the digest tidier would create exactly the gap an attacker
// wants: a region of the report that can be edited without detection.
func Digest(findings []Finding) string {
	type stable struct {
		CheckID      string         `json:"check_id"`
		Subdomain    string         `json:"subdomain"`
		ControlCodes []string       `json:"control_codes"`
		Status       Status         `json:"status"`
		Severity     Severity       `json:"severity"`
		Detail       string         `json:"detail"`
		Evidence     map[string]any `json:"evidence,omitempty"`
		Err          string         `json:"error,omitempty"`
	}

	out := make([]stable, 0, len(findings))
	for _, f := range findings {
		out = append(out, stable{
			CheckID:      f.CheckID,
			Subdomain:    f.Subdomain,
			ControlCodes: f.ControlCodes,
			Status:       f.Status,
			Severity:     f.Severity,
			Detail:       f.Detail,
			Evidence:     f.Evidence,
			Err:          f.Err,
		})
	}

	// Findings arrive in check-registration order, which is stable today but
	// would change if a check were renamed. Sorting makes the digest depend on
	// content alone.
	sort.Slice(out, func(i, j int) bool {
		if out[i].CheckID != out[j].CheckID {
			return out[i].CheckID < out[j].CheckID
		}
		return out[i].Detail < out[j].Detail
	})

	// json.Marshal orders map keys, so evidence maps serialise deterministically.
	data, err := json.Marshal(out)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
