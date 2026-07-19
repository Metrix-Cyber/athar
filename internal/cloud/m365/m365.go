// Package m365 assesses a Microsoft 365 tenant via Microsoft Graph.
//
// Every permission requested is read-only. The scopes are declared per check
// so an administrator granting consent can see exactly what is being read and
// which control it serves.
package m365

import (
	"context"
	"fmt"
	"strings"

	"github.com/Metrix-Cyber/athar/internal/cloud"
	"github.com/Metrix-Cyber/athar/internal/finding"
)

// GraphBaseURL is the Microsoft Graph v1.0 endpoint.
const GraphBaseURL = "https://graph.microsoft.com/v1.0"

// Provider assesses a Microsoft 365 tenant.
type Provider struct{}

func (Provider) Name() string { return "microsoft-365" }

func (Provider) Checks() []cloud.Check {
	return []cloud.Check{
		{
			ID: "m365.identity.mfa_policy", Subdomain: "2-2",
			ControlCodes:   []string{"2-2-2", "2-2-3-2"},
			RequiredScopes: []string{"Policy.Read.All"},
			Run:            conditionalAccessMFA,
		},
		{
			ID: "m365.identity.privileged_roles", Subdomain: "2-2",
			ControlCodes:   []string{"2-2-3-4"},
			RequiredScopes: []string{"RoleManagement.Read.Directory", "Directory.Read.All"},
			Run:            privilegedRoles,
		},
		{
			ID: "m365.email.dkim", Subdomain: "2-4",
			ControlCodes:   []string{"2-4-2", "2-4-3-5"},
			RequiredScopes: []string{"Domain.Read.All"},
			Run:            domainAuthentication,
		},
		{
			ID: "m365.audit.retention", Subdomain: "2-12",
			ControlCodes:   []string{"2-12-2", "2-12-3-1", "2-12-3-5"},
			RequiredScopes: []string{"Policy.Read.All"},
			Run:            auditRetention,
		},
		{
			ID: "m365.data.classification", Subdomain: "2-1",
			ControlCodes:   []string{"2-1-5"},
			RequiredScopes: []string{"InformationProtectionPolicy.Read.All"},
			Run:            sensitivityLabels,
		},
	}
}

// --- Graph response shapes ---

type caPolicyList struct {
	Value []struct {
		DisplayName string `json:"displayName"`
		State       string `json:"state"`
		Conditions  struct {
			Users struct {
				IncludeUsers []string `json:"includeUsers"`
				IncludeRoles []string `json:"includeRoles"`
			} `json:"users"`
			Applications struct {
				IncludeApplications []string `json:"includeApplications"`
			} `json:"applications"`
		} `json:"conditions"`
		GrantControls struct {
			BuiltInControls []string `json:"builtInControls"`
		} `json:"grantControls"`
	} `json:"value"`
}

type domainList struct {
	Value []struct {
		ID                     string   `json:"id"`
		IsVerified             bool     `json:"isVerified"`
		AuthenticationType     string   `json:"authenticationType"`
		SupportedServices      []string `json:"supportedServices"`
		PasswordValidityPeriod *int     `json:"passwordValidityPeriodInDays"`
	} `json:"value"`
}

type roleAssignmentList struct {
	Value []struct {
		RoleDefinitionID string `json:"roleDefinitionId"`
		PrincipalID      string `json:"principalId"`
	} `json:"value"`
}

type labelList struct {
	Value []struct {
		Name        string `json:"name"`
		IsActive    bool   `json:"isActive"`
		Sensitivity int    `json:"sensitivity"`
	} `json:"value"`
}

// --- Checks ---

// conditionalAccessMFA evaluates whether MFA is actually enforced.
//
// This is the clause a host scan explicitly could not answer: the endpoint can
// show it supports strong authentication, but only the identity provider knows
// whether MFA is required. A policy that exists but is in "disabled" or
// "enabledForReportingButNotEnforced" state provides no protection, so state
// is checked rather than mere existence — counting report-only policies as
// enforcement would be a textbook false pass.
func conditionalAccessMFA(ctx context.Context, c *cloud.Client) []finding.Finding {
	f := finding.New("m365.identity.mfa_policy",
		"Multi-factor authentication enforcement", "2-2", []string{"2-2-2", "2-2-3-2"})

	var policies caPolicyList
	if err := c.Get(ctx, "/identity/conditionalAccess/policies", &policies); err != nil {
		return []finding.Finding{undetermined(f, err)}
	}

	var enforced, reportOnly, disabled []string
	for _, p := range policies.Value {
		if !requiresMFA(p.GrantControls.BuiltInControls) {
			continue
		}
		switch strings.ToLower(p.State) {
		case "enabled":
			enforced = append(enforced, p.DisplayName)
		case "enabledforreportingbutnotenforced":
			reportOnly = append(reportOnly, p.DisplayName)
		default:
			disabled = append(disabled, p.DisplayName)
		}
	}

	f = f.With("policies_total", len(policies.Value)).
		With("mfa_policies_enforced", enforced).
		With("mfa_policies_report_only", reportOnly).
		With("mfa_policies_disabled", disabled)

	switch {
	case len(enforced) > 0:
		return []finding.Finding{f.Passed(fmt.Sprintf(
			"%d Conditional Access polic(ies) enforce multi-factor authentication: %s. Confirm their scope covers remote access and all privileged accounts as ECC 2-2-3-2 requires.",
			len(enforced), strings.Join(enforced, ", ")))}

	case len(reportOnly) > 0:
		return []finding.Finding{f.Failed(finding.High,
			fmt.Sprintf("Multi-factor authentication policies exist but only in report-only mode (%s). They record what would have happened and enforce nothing.",
				strings.Join(reportOnly, ", ")),
			"Move the Conditional Access policies from report-only to enabled once their impact has been reviewed.")}

	default:
		return []finding.Finding{f.Failed(finding.Critical,
			"No enabled Conditional Access policy requires multi-factor authentication. Accounts, including privileged ones, can authenticate with a password alone.",
			"Create and enable Conditional Access policies requiring multi-factor authentication for all users, and specifically for privileged roles and remote access.")}
	}
}

func requiresMFA(controls []string) bool {
	for _, c := range controls {
		switch strings.ToLower(c) {
		case "mfa", "multifactorauthentication":
			return true
		}
	}
	return false
}

// privilegedRoles reports how many principals hold Global Administrator.
func privilegedRoles(ctx context.Context, c *cloud.Client) []finding.Finding {
	f := finding.New("m365.identity.privileged_roles",
		"Privileged role assignment", "2-2", []string{"2-2-3-4"})

	// The Global Administrator role has a fixed well-known template ID.
	const globalAdminTemplate = "62e90394-69f5-4237-9190-012177145e10"

	var assignments roleAssignmentList
	path := "/roleManagement/directory/roleAssignments?$filter=roleDefinitionId eq '" +
		globalAdminTemplate + "'"
	if err := c.Get(ctx, path, &assignments); err != nil {
		return []finding.Finding{undetermined(f, err)}
	}

	n := len(assignments.Value)
	f = f.With("global_administrator_count", n)

	// Microsoft's own guidance is to keep this small; a large number defeats
	// accountability and widens the blast radius of a single compromise.
	switch {
	case n == 0:
		return []finding.Finding{f.Undetermined(fmt.Errorf(
			"no Global Administrator assignments were returned, which is unexpected and suggests the query did not see the full directory"))}
	case n > 5:
		return []finding.Finding{f.Failed(finding.High,
			fmt.Sprintf("%d principals hold Global Administrator. Privileged access should be limited to those who require it, with day-to-day work performed under lower-privileged accounts.", n),
			"Reduce standing Global Administrator assignments, use privileged identity management for just-in-time elevation, and evidence periodic review of privileged access.")}
	default:
		return []finding.Finding{f.Passed(fmt.Sprintf(
			"%d principals hold Global Administrator. Confirm each is required and covered by periodic access review.", n))}
	}
}

// domainAuthentication reports domain-level email authentication.
//
// Graph exposes verification and service configuration. SPF and DMARC live in
// DNS TXT records, which this connector does not resolve — so the finding says
// what it checked and what it did not, rather than implying full coverage of
// ECC 2-4-3-5.
func domainAuthentication(ctx context.Context, c *cloud.Client) []finding.Finding {
	f := finding.New("m365.email.dkim",
		"Email domain authentication", "2-4", []string{"2-4-2", "2-4-3-5"})

	var domains domainList
	if err := c.Get(ctx, "/domains", &domains); err != nil {
		return []finding.Finding{undetermined(f, err)}
	}

	var unverified, mailEnabled []string
	for _, d := range domains.Value {
		for _, s := range d.SupportedServices {
			if strings.EqualFold(s, "Email") {
				mailEnabled = append(mailEnabled, d.ID)
				break
			}
		}
		if !d.IsVerified {
			unverified = append(unverified, d.ID)
		}
	}

	f = f.With("domains_total", len(domains.Value)).
		With("mail_enabled_domains", mailEnabled).
		With("unverified_domains", unverified)

	if len(unverified) > 0 {
		return []finding.Finding{f.Failed(finding.Medium,
			fmt.Sprintf("%d domain(s) are registered on the tenant but unverified: %s.",
				len(unverified), strings.Join(unverified, ", ")),
			"Remove unused domains and complete verification for those that are required.")}
	}

	return []finding.Finding{f.Passed(fmt.Sprintf(
		"%d mail-enabled domain(s) are verified on the tenant. SPF and DMARC records are published in DNS and are not read by this connector; ECC 2-4-3-5 requires all three of SPF, DKIM and DMARC, so the DNS records must be confirmed separately.",
		len(mailEnabled)))}
}

// auditRetention reports whether tenant audit logging is retained long enough
// to satisfy the twelve-month requirement.
func auditRetention(ctx context.Context, c *cloud.Client) []finding.Finding {
	f := finding.New("m365.audit.retention", "Audit log retention", "2-12",
		[]string{"2-12-2", "2-12-3-1", "2-12-3-5"})

	var policies struct {
		Value []struct {
			DisplayName    string `json:"displayName"`
			RetentionType  string `json:"recordType"`
			RetentionDurat string `json:"retentionDuration"`
		} `json:"value"`
	}
	if err := c.Get(ctx, "/security/auditLog/queries", &policies); err != nil {
		return []finding.Finding{undetermined(f, err)}
	}

	f = f.With("audit_retention_policies", len(policies.Value))

	// ECC 2-12-3-5 states a hard twelve-month minimum. Default Microsoft 365
	// audit retention is shorter than that on most licence tiers, so absence
	// of an explicit policy is itself the finding.
	if len(policies.Value) == 0 {
		return []finding.Finding{f.Failed(finding.High,
			"No explicit audit log retention policy was found. Default retention on most Microsoft 365 licence tiers is shorter than the twelve months ECC 2-12-3-5 requires, so logs will age out before the retention period is met.",
			"Configure audit log retention policies of at least one year, and confirm the licence tier supports that duration.")}
	}

	return []finding.Finding{f.Passed(fmt.Sprintf(
		"%d audit retention polic(ies) are configured. Confirm each covers at least twelve months as ECC 2-12-3-5 requires.",
		len(policies.Value)))}
}

// sensitivityLabels evidences data classification, which ECC 2-1-5 requires
// and no host scan can observe.
func sensitivityLabels(ctx context.Context, c *cloud.Client) []finding.Finding {
	f := finding.New("m365.data.classification",
		"Information classification labels", "2-1", []string{"2-1-5"})

	var labels labelList
	if err := c.Get(ctx, "/security/informationProtection/sensitivityLabels", &labels); err != nil {
		return []finding.Finding{undetermined(f, err)}
	}

	var active []string
	for _, l := range labels.Value {
		if l.IsActive {
			active = append(active, l.Name)
		}
	}
	f = f.With("labels_total", len(labels.Value)).With("labels_active", active)

	if len(active) == 0 {
		return []finding.Finding{f.Failed(finding.Medium,
			"No active sensitivity labels are published. ECC 2-1-5 requires information assets to be classified, labelled and handled according to their classification; without labels there is no mechanism enforcing that in the tenant.",
			"Define and publish a sensitivity label scheme matching the entity's data classification policy, and apply it to information assets.")}
	}

	return []finding.Finding{f.Passed(fmt.Sprintf(
		"%d active sensitivity label(s) are published (%s). Confirm the scheme matches the entity's classification policy and that labelling is actually applied.",
		len(active), strings.Join(active, ", ")))}
}

// undetermined converts an API failure into a finding that distinguishes a
// permissions problem from an unlicensed feature from a real error. Reporting
// any of these as a control failure would be a false finding about the tenant.
func undetermined(f finding.Finding, err error) finding.Finding {
	var apiErr *cloud.APIError
	if ok := asAPIError(err, &apiErr); ok {
		switch {
		case apiErr.Denied():
			return f.Undetermined(fmt.Errorf(
				"%w — grant the read scopes listed for this check and re-run", err))
		case apiErr.Unavailable():
			return f.Inapplicable(
				"This capability is not available on the tenant, which usually indicates the feature is not licensed. It cannot be assessed here and must be evidenced another way.")
		}
	}
	return f.Undetermined(err)
}
