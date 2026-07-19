// Package google assesses a Google Workspace tenant via the Admin SDK.
//
// All scopes requested are the read-only variants. Where an equivalent
// Microsoft 365 check exists, the ECC control mapping is identical — the
// control belongs to the framework, not to the vendor.
package google

import (
	"context"
	"fmt"
	"strings"

	"github.com/Metrix-Cyber/athar/internal/cloud"
	"github.com/Metrix-Cyber/athar/internal/finding"
)

// AdminBaseURL is the Google Admin SDK Directory API endpoint.
const AdminBaseURL = "https://admin.googleapis.com/admin"

// Provider assesses a Google Workspace tenant.
type Provider struct{}

func (Provider) Name() string { return "google-workspace" }

func (Provider) Checks() []cloud.Check {
	return []cloud.Check{
		{
			ID: "google.identity.two_step_verification", Subdomain: "2-2",
			ControlCodes:   []string{"2-2-2", "2-2-3-2"},
			RequiredScopes: []string{"admin.directory.user.readonly"},
			Run:            twoStepVerification,
		},
		{
			ID: "google.identity.super_admins", Subdomain: "2-2",
			ControlCodes:   []string{"2-2-3-4"},
			RequiredScopes: []string{"admin.directory.user.readonly"},
			Run:            superAdmins,
		},
		{
			ID: "google.identity.suspended_accounts", Subdomain: "2-2",
			ControlCodes:   []string{"2-2-3-5"},
			RequiredScopes: []string{"admin.directory.user.readonly"},
			Run:            dormantAccounts,
		},
		{
			ID: "google.email.domains", Subdomain: "2-4",
			ControlCodes:   []string{"2-4-2", "2-4-3-5"},
			RequiredScopes: []string{"admin.directory.domain.readonly"},
			Run:            domainVerification,
		},
	}
}

// userList is the Admin SDK users.list response.
type userList struct {
	Users []User `json:"users"`
	Next  string `json:"nextPageToken"`
}

// User is one directory account.
type User struct {
	PrimaryEmail    string `json:"primaryEmail"`
	Suspended       bool   `json:"suspended"`
	Archived        bool   `json:"archived"`
	IsAdmin         bool   `json:"isAdmin"`
	IsDelegated     bool   `json:"isDelegatedAdmin"`
	IsEnrolledIn2Sv bool   `json:"isEnrolledIn2Sv"`
	IsEnforcedIn2Sv bool   `json:"isEnforcedIn2Sv"`
	LastLoginTime   string `json:"lastLoginTime"`
}

type domainList struct {
	Domains []struct {
		DomainName string `json:"domainName"`
		Verified   bool   `json:"verified"`
		IsPrimary  bool   `json:"isPrimary"`
	} `json:"domains"`
}

// listUsers pages through the directory.
//
// Paging is not optional: the API caps a page at 500 accounts, and stopping at
// the first page would silently assess a fraction of the directory while
// reporting as though it had seen all of it — a false pass on any tenant
// larger than a small business.
func listUsers(ctx context.Context, c *cloud.Client) ([]User, error) {
	var all []User
	page := ""
	for {
		path := "/directory/v1/users?customer=my_customer&maxResults=500&projection=full"
		if page != "" {
			path += "&pageToken=" + page
		}
		var resp userList
		if err := c.Get(ctx, path, &resp); err != nil {
			return nil, err
		}
		all = append(all, resp.Users...)
		if resp.Next == "" {
			return all, nil
		}
		page = resp.Next
		// Guard against a server that keeps returning a token.
		if len(all) > 100000 {
			return all, nil
		}
	}
}

// ActiveUsers returns accounts that can currently sign in.
func ActiveUsers(users []User) []User {
	var out []User
	for _, u := range users {
		if !u.Suspended && !u.Archived {
			out = append(out, u)
		}
	}
	return out
}

// twoStepVerification evaluates 2SV coverage across active accounts.
//
// Enrolment and enforcement are reported separately: a user who has enrolled
// voluntarily can also un-enrol, so enrolment without enforcement is not the
// control ECC 2-2-3-2 asks for.
func twoStepVerification(ctx context.Context, c *cloud.Client) []finding.Finding {
	f := finding.New("google.identity.two_step_verification",
		"Two-step verification", "2-2", []string{"2-2-2", "2-2-3-2"})

	users, err := listUsers(ctx, c)
	if err != nil {
		return []finding.Finding{undetermined(f, err)}
	}

	active := ActiveUsers(users)
	var notEnrolled, notEnforced, adminsWithout []string
	for _, u := range active {
		if !u.IsEnrolledIn2Sv {
			notEnrolled = append(notEnrolled, u.PrimaryEmail)
			if u.IsAdmin || u.IsDelegated {
				adminsWithout = append(adminsWithout, u.PrimaryEmail)
			}
			continue
		}
		if !u.IsEnforcedIn2Sv {
			notEnforced = append(notEnforced, u.PrimaryEmail)
		}
	}

	f = f.With("active_accounts", len(active)).
		With("not_enrolled_count", len(notEnrolled)).
		With("enrolled_but_not_enforced_count", len(notEnforced)).
		With("administrators_without_2sv", adminsWithout)

	switch {
	case len(adminsWithout) > 0:
		return []finding.Finding{f.Failed(finding.Critical,
			fmt.Sprintf("%d administrator account(s) are not enrolled in two-step verification: %s. A privileged account protected by a password alone is the single highest-value target in the tenant.",
				len(adminsWithout), strings.Join(adminsWithout, ", ")),
			"Enforce two-step verification for all administrators immediately, then extend enforcement to all users.")}

	case len(notEnrolled) > 0:
		return []finding.Finding{f.Failed(finding.High,
			fmt.Sprintf("%d of %d active accounts are not enrolled in two-step verification.",
				len(notEnrolled), len(active)),
			"Enforce two-step verification tenant-wide through an enrollment policy.")}

	case len(notEnforced) > 0:
		return []finding.Finding{f.Failed(finding.Medium,
			fmt.Sprintf("All %d active accounts are enrolled in two-step verification, but %d are not covered by an enforcement policy. Voluntary enrolment can be reversed by the user.",
				len(active), len(notEnforced)),
			"Apply a two-step verification enforcement policy so the control cannot be turned off by the account holder.")}
	}

	return []finding.Finding{f.Passed(fmt.Sprintf(
		"All %d active accounts are enrolled in and covered by enforced two-step verification.", len(active)))}
}

// superAdmins reports the count of accounts holding administrative rights.
func superAdmins(ctx context.Context, c *cloud.Client) []finding.Finding {
	f := finding.New("google.identity.super_admins",
		"Administrative account assignment", "2-2", []string{"2-2-3-4"})

	users, err := listUsers(ctx, c)
	if err != nil {
		return []finding.Finding{undetermined(f, err)}
	}

	var admins, delegated []string
	for _, u := range ActiveUsers(users) {
		switch {
		case u.IsAdmin:
			admins = append(admins, u.PrimaryEmail)
		case u.IsDelegated:
			delegated = append(delegated, u.PrimaryEmail)
		}
	}

	f = f.With("super_administrators", admins).
		With("delegated_administrators", delegated)

	if len(admins) > 4 {
		return []finding.Finding{f.Failed(finding.High,
			fmt.Sprintf("%d accounts hold super administrator rights: %s. Privileged access should be limited to those requiring it, with routine work performed under separate unprivileged accounts.",
				len(admins), strings.Join(admins, ", ")),
			"Reduce super administrator assignments, use delegated roles scoped to specific functions, and evidence periodic review of privileged access.")}
	}

	return []finding.Finding{f.Passed(fmt.Sprintf(
		"%d super administrator(s) and %d delegated administrator(s). Confirm each is required and covered by periodic access review.",
		len(admins), len(delegated)))}
}

// dormantAccounts reports active accounts that have never signed in, which
// evidences whether the periodic identity review ECC 2-2-3-5 requires happens.
func dormantAccounts(ctx context.Context, c *cloud.Client) []finding.Finding {
	f := finding.New("google.identity.suspended_accounts",
		"Dormant account review", "2-2", []string{"2-2-3-5"})

	users, err := listUsers(ctx, c)
	if err != nil {
		return []finding.Finding{undetermined(f, err)}
	}

	active := ActiveUsers(users)
	var neverLoggedIn []string
	for _, u := range active {
		// The API returns the Unix epoch for accounts that have never signed
		// in; treating that as a valid recent timestamp would hide exactly the
		// accounts this check exists to surface.
		if u.LastLoginTime == "" || strings.HasPrefix(u.LastLoginTime, "1970-01-01") {
			neverLoggedIn = append(neverLoggedIn, u.PrimaryEmail)
		}
	}

	f = f.With("active_accounts", len(active)).
		With("never_signed_in", neverLoggedIn)

	if len(neverLoggedIn) > 0 {
		return []finding.Finding{f.Failed(finding.Medium,
			fmt.Sprintf("%d active account(s) have never signed in: %s. Unused enabled accounts widen the attack surface and indicate identities are not being reviewed.",
				len(neverLoggedIn), strings.Join(neverLoggedIn, ", ")),
			"Suspend or remove accounts that are not in use, and evidence periodic review of identities and access rights.")}
	}

	return []finding.Finding{f.Passed(fmt.Sprintf(
		"All %d active accounts have signed in at least once.", len(active)))}
}

// domainVerification reports domain configuration for the tenant.
func domainVerification(ctx context.Context, c *cloud.Client) []finding.Finding {
	f := finding.New("google.email.domains",
		"Email domain configuration", "2-4", []string{"2-4-2", "2-4-3-5"})

	var domains domainList
	if err := c.Get(ctx, "/directory/v1/customer/my_customer/domains", &domains); err != nil {
		return []finding.Finding{undetermined(f, err)}
	}

	var unverified []string
	for _, d := range domains.Domains {
		if !d.Verified {
			unverified = append(unverified, d.DomainName)
		}
	}

	f = f.With("domains_total", len(domains.Domains)).
		With("unverified_domains", unverified)

	if len(unverified) > 0 {
		return []finding.Finding{f.Failed(finding.Medium,
			fmt.Sprintf("%d domain(s) on the tenant are unverified: %s.",
				len(unverified), strings.Join(unverified, ", ")),
			"Complete verification for required domains and remove those no longer in use.")}
	}

	return []finding.Finding{f.Passed(fmt.Sprintf(
		"All %d tenant domain(s) are verified. SPF, DKIM and DMARC records live in DNS and are not read by this connector; ECC 2-4-3-5 requires all three, so those records must be confirmed separately.",
		len(domains.Domains)))}
}

func undetermined(f finding.Finding, err error) finding.Finding {
	var apiErr *cloud.APIError
	if asAPIError(err, &apiErr) {
		switch {
		case apiErr.Denied():
			return f.Undetermined(fmt.Errorf(
				"%w — grant the read-only scopes listed for this check and re-run", err))
		case apiErr.Unavailable():
			return f.Inapplicable(
				"This capability is not available on the tenant, which usually indicates the edition does not include it.")
		}
	}
	return f.Undetermined(err)
}
