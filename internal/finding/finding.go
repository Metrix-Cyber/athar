// Package finding defines the structured output of every check.
//
// The scanner's only job is to produce these. Rendering them into a report
// lives outside the binary so the free/paid presentation decision stays open.
package finding

import "time"

// Status is the outcome of a single check.
type Status string

const (
	// Pass means the check ran and the control requirement was met.
	Pass Status = "pass"
	// Fail means the check ran and the requirement was not met.
	Fail Status = "fail"
	// Unknown means the check could not determine an answer — missing
	// privileges, an absent subsystem, or an unexpected platform state.
	//
	// Unknown is reported, never silently dropped. A tool that hides what it
	// could not see reads as a clean result and destroys trust with exactly
	// the security-literate buyers this product targets.
	Unknown Status = "unknown"
	// NotApplicable means the check does not apply to this host (e.g. a web
	// server check on a host running no web server).
	NotApplicable Status = "not_applicable"
)

// Severity ranks a failing finding. Passing findings carry Info.
type Severity string

const (
	Critical Severity = "critical"
	High     Severity = "high"
	Medium   Severity = "medium"
	Low      Severity = "low"
	Info     Severity = "info"
)

// Finding is the result of one check against one host.
type Finding struct {
	// CheckID is the scanner's stable identifier, e.g. "win.iam.local_admins".
	CheckID string `json:"check_id"`
	// Title is a short human-readable statement of what was checked.
	Title string `json:"title"`
	// ControlCodes are the ECC-2:2024 codes this check provides evidence for,
	// in main-sub-control-subcontrol form (e.g. "2-2-1-3"). A check may map to
	// several, and the same finding maps onto other frameworks later via the
	// control catalog rather than by re-running anything.
	ControlCodes []string `json:"control_codes"`
	// Subdomain is the ECC subdomain, e.g. "2-2". Kept denormalized so reports
	// can group without loading the catalog.
	Subdomain string `json:"subdomain"`

	Status   Status   `json:"status"`
	Severity Severity `json:"severity"`

	// Detail explains the observed state in one or two sentences.
	Detail string `json:"detail"`
	// Evidence is the raw observed values behind the verdict. This is what
	// makes the finding auditable rather than an assertion.
	Evidence map[string]any `json:"evidence,omitempty"`
	// Remediation is a short fix instruction. Detailed guidance is generated
	// later by the platform, not embedded in the binary.
	Remediation string `json:"remediation,omitempty"`
	// Err records why Status is Unknown.
	Err string `json:"error,omitempty"`

	ObservedAt time.Time `json:"observed_at"`
}

// New returns a Finding stamped with the current time.
func New(checkID, title, subdomain string, codes []string) Finding {
	return Finding{
		CheckID:      checkID,
		Title:        title,
		Subdomain:    subdomain,
		ControlCodes: codes,
		Evidence:     map[string]any{},
		ObservedAt:   time.Now().UTC(),
	}
}

// Passed marks the finding as satisfying its control.
func (f Finding) Passed(detail string) Finding {
	f.Status, f.Severity, f.Detail = Pass, Info, detail
	return f
}

// Failed marks the finding as not satisfying its control.
func (f Finding) Failed(sev Severity, detail, remediation string) Finding {
	f.Status, f.Severity, f.Detail, f.Remediation = Fail, sev, detail, remediation
	return f
}

// Undetermined marks the finding as unresolvable, recording why.
func (f Finding) Undetermined(err error) Finding {
	f.Status, f.Severity = Unknown, Info
	if err != nil {
		f.Err = err.Error()
	}
	return f
}

// Inapplicable marks the check as not relevant to this host.
func (f Finding) Inapplicable(detail string) Finding {
	f.Status, f.Severity, f.Detail = NotApplicable, Info, detail
	return f
}

// With attaches an evidence value.
func (f Finding) With(key string, val any) Finding {
	if f.Evidence == nil {
		f.Evidence = map[string]any{}
	}
	f.Evidence[key] = val
	return f
}
