package framework

// Assessability describes how a subdomain can be evidenced.
//
// This classification is the honest core of the product. A compliance report
// that silently omits what it did not examine reads as a clean bill of health;
// one that states plainly which controls are outside a scanner's reach is both
// truthful and considerably more useful, because the unscannable portion is
// exactly the work an assessor must do.
type Assessability string

const (
	// Automated: a host scan produces direct technical evidence.
	Automated Assessability = "automated"
	// Documentary: satisfied by artefacts the entity holds — policies,
	// registers, contracts, training records — which must be collected and
	// reviewed rather than scanned.
	Documentary Assessability = "documentary"
	// Assessor: requires professional judgement, interview or observation.
	Assessor Assessability = "assessor"
	// Partial: a scan evidences part of the subdomain; the rest needs one of
	// the above.
	Partial Assessability = "partial"
)

// coverage classifies every ECC-2:2024 subdomain.
//
// Rationale for the unscannable ones is deliberately explicit: an assessor
// reading the report should be able to see why a subdomain was not scanned and
// agree with the reasoning, rather than wondering what the tool missed.
var coverage = map[string]struct {
	Level  Assessability
	Reason string
}{
	// Domain 1 — Governance. Policy, process and human controls throughout.
	"1-1":  {Documentary, "Requires an approved cybersecurity strategy document and evidence of executive sponsorship."},
	"1-2":  {Documentary, "Requires evidence of a cybersecurity function, its mandate and its reporting line."},
	"1-3":  {Partial, "Policy documents must be reviewed; technical enforcement of some policy settings is evidenced by this scan."},
	"1-4":  {Documentary, "Requires defined and approved cybersecurity roles and responsibilities."},
	"1-5":  {Documentary, "Requires a risk management methodology and completed risk assessments."},
	"1-6":  {Documentary, "Requires evidence of cybersecurity requirements within project management."},
	"1-7":  {Assessor, "Requires review of the entity's regulatory obligations and compliance position."},
	"1-8":  {Documentary, "Requires periodic review and audit records."},
	"1-9":  {Documentary, "Requires HR security procedures covering screening, onboarding and termination."},
	"1-10": {Documentary, "Requires awareness programme materials and training completion records."},

	// Domain 2 — Defence. Largely technical, and where this scanner operates.
	"2-1":  {Partial, "Host inventory is collected automatically; asset classification, labelling and the acceptable use policy require review."},
	"2-2":  {Partial, "Local account, password, lockout and privilege configuration is evidenced; identity governance and periodic access review require evidence."},
	"2-3":  {Partial, "Endpoint protection, session lock and removable media settings are evidenced; procedures require review."},
	"2-4":  {Partial, "Office macro policy is evidenced; mail gateway filtering, DKIM/SPF/DMARC and mail security procedures require separate assessment."},
	"2-5":  {Partial, "Host firewall, exposed services, protocols and shares are evidenced; network segmentation, IPS, DNS security and wireless controls require network-level assessment."},
	"2-6":  {Partial, "Device management enrolment and removable media encryption policy are evidenced; the mobile device management programme requires review."},
	"2-7":  {Partial, "Encryption capability and policy are evidenced; data classification and handling require review."},
	"2-8":  {Partial, "Protocol configuration and certificate hygiene are evidenced; alignment with the National Cryptographic Standards and key lifecycle management require assessment."},
	"2-9":  {Partial, "Backup capability is evidenced; backup scheduling, protection and restore testing require evidence."},
	"2-10": {Partial, "Patch state and update configuration are evidenced; the vulnerability management programme and its remediation SLAs require review."},
	"2-11": {Assessor, "Penetration testing is an activity; requires test reports, scope and remediation tracking."},
	"2-12": {Partial, "Audit policy, logging configuration and log forwarding are evidenced; SIEM coverage, monitoring and the 12-month retention requirement must be confirmed on the collection platform."},
	"2-13": {Documentary, "Requires incident response plans, threat intelligence sources and incident records."},
	"2-14": {Assessor, "Physical security requires site inspection."},
	"2-15": {Partial, "Locally hosted web server configuration is evidenced where present; application security testing requires separate assessment."},

	// Domain 3 — Resilience.
	"3-1": {Documentary, "Requires business continuity and disaster recovery plans, and evidence of testing."},

	// Domain 4 — Third-party and cloud.
	"4-1": {Documentary, "Requires third-party contracts, cybersecurity clauses and supplier assessments."},
	"4-2": {Documentary, "Requires cloud service agreements, hosting arrangements and data location evidence."},
}

// Coverage returns how a subdomain can be evidenced, and why.
func (c *Catalog) Coverage(subdomain string) (Assessability, string) {
	if v, ok := coverage[subdomain]; ok {
		return v.Level, v.Reason
	}
	return Assessor, "Assessment approach not classified."
}

// CoverageSummary counts subdomains by assessability, for reporting the
// scanner's reach against the whole framework.
func (c *Catalog) CoverageSummary() map[Assessability]int {
	out := map[Assessability]int{}
	for _, s := range c.Subdomains {
		lvl, _ := c.Coverage(s.Code)
		out[lvl]++
	}
	return out
}
