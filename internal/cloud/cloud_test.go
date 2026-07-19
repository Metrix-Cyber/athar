package cloud_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Metrix-Cyber/athar/internal/cloud"
	"github.com/Metrix-Cyber/athar/internal/cloud/google"
	"github.com/Metrix-Cyber/athar/internal/cloud/m365"
	"github.com/Metrix-Cyber/athar/internal/finding"
)

// These tests are the only verification this code gets: there is no live
// Microsoft 365 or Google Workspace tenant to run against. They therefore
// cover the cases that would silently produce a wrong finding, not the happy
// path alone — a connector that reports a control as satisfied when it is not
// is the most damaging thing this project can ship.

// testClient serves canned responses for a path, so provider logic is
// exercised without network access.
func testClient(t *testing.T, status int, responses map[string]string) (*cloud.Client, func()) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for path, body := range responses {
			if strings.Contains(r.URL.Path+"?"+r.URL.RawQuery, path) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(status)
				_, _ = w.Write([]byte(body))
				return
			}
		}
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"error":"not found"}`))
	}))
	c := &cloud.Client{
		HTTP:    srv.Client(),
		BaseURL: srv.URL,
		Token:   func(context.Context) (string, error) { return "test-token", nil },
	}
	return c, srv.Close
}

func findByID(fs []finding.Finding, id string) *finding.Finding {
	for i := range fs {
		if fs[i].CheckID == id {
			return &fs[i]
		}
	}
	return nil
}

// A Conditional Access policy in report-only mode enforces nothing. Counting
// it as MFA coverage would be a false pass on the single most important
// identity control.
func TestM365ReportOnlyPolicyIsNotEnforcement(t *testing.T) {
	body := `{"value":[
      {"displayName":"Require MFA","state":"enabledForReportingButNotEnforced",
       "grantControls":{"builtInControls":["mfa"]}}
    ]}`
	c, done := testClient(t, 200, map[string]string{"conditionalAccess": body})
	defer done()

	fs := m365.Provider{}.Checks()[0].Run(context.Background(), c)
	f := findByID(fs, "m365.identity.mfa_policy")
	if f == nil {
		t.Fatal("no finding produced")
	}
	if f.Status != finding.Fail {
		t.Errorf("status = %q, want fail: a report-only policy enforces nothing", f.Status)
	}
	if f.Severity != finding.High {
		t.Errorf("severity = %q, want high", f.Severity)
	}
}

func TestM365EnabledPolicyPasses(t *testing.T) {
	body := `{"value":[
      {"displayName":"Require MFA","state":"enabled",
       "grantControls":{"builtInControls":["mfa"]}}
    ]}`
	c, done := testClient(t, 200, map[string]string{"conditionalAccess": body})
	defer done()

	f := findByID(m365.Provider{}.Checks()[0].Run(context.Background(), c), "m365.identity.mfa_policy")
	if f.Status != finding.Pass {
		t.Errorf("status = %q, want pass", f.Status)
	}
}

// No MFA policy at all is the worst case and must be critical, not merely a
// failure among others.
func TestM365NoMFAPolicyIsCritical(t *testing.T) {
	c, done := testClient(t, 200, map[string]string{"conditionalAccess": `{"value":[]}`})
	defer done()

	f := findByID(m365.Provider{}.Checks()[0].Run(context.Background(), c), "m365.identity.mfa_policy")
	if f.Status != finding.Fail || f.Severity != finding.Critical {
		t.Errorf("got %s/%s, want fail/critical", f.Status, f.Severity)
	}
}

// A denied scope is not evidence about the tenant. Reporting it as a failure
// would tell a customer a control is missing when it was simply not readable.
func TestM365DeniedScopeIsUndeterminedNotFailure(t *testing.T) {
	c, done := testClient(t, 403, map[string]string{"conditionalAccess": `{"error":"denied"}`})
	defer done()

	f := findByID(m365.Provider{}.Checks()[0].Run(context.Background(), c), "m365.identity.mfa_policy")
	if f.Status != finding.Unknown {
		t.Errorf("status = %q, want unknown: a 403 is a permissions problem, not a finding", f.Status)
	}
	if !strings.Contains(f.Err, "scope") {
		t.Errorf("error should tell the operator to grant scopes, got %q", f.Err)
	}
}

// An unlicensed feature is not a control failure either.
func TestM365UnlicensedFeatureIsNotApplicable(t *testing.T) {
	c, done := testClient(t, 404, map[string]string{"sensitivityLabels": `{}`})
	defer done()

	var chk cloud.Check
	for _, x := range (m365.Provider{}).Checks() {
		if x.ID == "m365.data.classification" {
			chk = x
		}
	}
	f := findByID(chk.Run(context.Background(), c), "m365.data.classification")
	if f.Status != finding.NotApplicable {
		t.Errorf("status = %q, want not_applicable for an unlicensed feature", f.Status)
	}
}

// An administrator without 2SV must outrank a general enrolment shortfall:
// it is the highest-value target in the tenant.
func TestGoogleAdminWithout2SVIsCritical(t *testing.T) {
	body := `{"users":[
      {"primaryEmail":"admin@example.sa","isAdmin":true,"isEnrolledIn2Sv":false,"lastLoginTime":"2026-07-01T10:00:00.000Z"},
      {"primaryEmail":"user@example.sa","isAdmin":false,"isEnrolledIn2Sv":true,"isEnforcedIn2Sv":true,"lastLoginTime":"2026-07-01T10:00:00.000Z"}
    ]}`
	c, done := testClient(t, 200, map[string]string{"users": body})
	defer done()

	f := findByID((google.Provider{}).Checks()[0].Run(context.Background(), c),
		"google.identity.two_step_verification")
	if f.Status != finding.Fail || f.Severity != finding.Critical {
		t.Errorf("got %s/%s, want fail/critical for an admin without 2SV", f.Status, f.Severity)
	}
}

// Voluntary enrolment can be reversed by the user, so enrolled-but-unenforced
// is not the control ECC 2-2-3-2 asks for.
func TestGoogleEnrolledButNotEnforcedStillFails(t *testing.T) {
	body := `{"users":[
      {"primaryEmail":"user@example.sa","isEnrolledIn2Sv":true,"isEnforcedIn2Sv":false,"lastLoginTime":"2026-07-01T10:00:00.000Z"}
    ]}`
	c, done := testClient(t, 200, map[string]string{"users": body})
	defer done()

	f := findByID((google.Provider{}).Checks()[0].Run(context.Background(), c),
		"google.identity.two_step_verification")
	if f.Status != finding.Fail {
		t.Errorf("status = %q, want fail: enrolment without enforcement is reversible", f.Status)
	}
}

// Suspended and archived accounts cannot sign in and must not be counted as
// active, or every tenant with staff turnover reports false failures.
func TestGoogleSuspendedAccountsExcluded(t *testing.T) {
	users := []google.User{
		{PrimaryEmail: "a@example.sa"},
		{PrimaryEmail: "b@example.sa", Suspended: true},
		{PrimaryEmail: "c@example.sa", Archived: true},
	}
	if got := google.ActiveUsers(users); len(got) != 1 || got[0].PrimaryEmail != "a@example.sa" {
		t.Errorf("ActiveUsers = %v, want only the unsuspended account", got)
	}
}

// The API returns the Unix epoch for accounts that have never signed in.
// Treating it as a valid timestamp hides exactly the accounts the check exists
// to surface.
func TestGoogleEpochLastLoginCountsAsNeverSignedIn(t *testing.T) {
	body := `{"users":[
      {"primaryEmail":"dormant@example.sa","lastLoginTime":"1970-01-01T00:00:00.000Z"},
      {"primaryEmail":"active@example.sa","lastLoginTime":"2026-07-01T10:00:00.000Z"}
    ]}`
	c, done := testClient(t, 200, map[string]string{"users": body})
	defer done()

	var chk cloud.Check
	for _, x := range (google.Provider{}).Checks() {
		if x.ID == "google.identity.suspended_accounts" {
			chk = x
		}
	}
	f := findByID(chk.Run(context.Background(), c), "google.identity.suspended_accounts")
	if f.Status != finding.Fail {
		t.Fatalf("status = %q, want fail", f.Status)
	}
	never, _ := f.Evidence["never_signed_in"].([]string)
	if len(never) != 1 || never[0] != "dormant@example.sa" {
		t.Errorf("never_signed_in = %v, want the epoch-timestamped account only", never)
	}
}

// isReadOnlyScope reports whether a scope grants read access only.
//
// Substring matching does not work here and the first version of this test
// proved it: "RoleManagement.Read.Directory" contains "manage" and was flagged
// as write-capable despite being read-only. Scopes are structured, so they are
// parsed rather than pattern-matched.
func isReadOnlyScope(scope string) bool {
	// Google Admin SDK: dotted path ending in "readonly",
	// e.g. admin.directory.user.readonly
	if strings.HasSuffix(strings.ToLower(scope), ".readonly") {
		return true
	}

	// Microsoft Graph: Resource.Permission[.Scope], where the permission is
	// the second segment — Policy.Read.All, RoleManagement.Read.Directory.
	// "ReadWrite" in that position is write-capable.
	parts := strings.Split(scope, ".")
	if len(parts) >= 2 {
		return strings.EqualFold(parts[1], "Read")
	}
	return false
}

// Every declared scope must grant read access only. A connector that can write
// is one no security team should grant consent to, and the whole argument for
// running this against a production tenant rests on that being true.
func TestAllRequestedScopesAreReadOnly(t *testing.T) {
	for _, p := range []cloud.Provider{m365.Provider{}, google.Provider{}} {
		for _, chk := range p.Checks() {
			if len(chk.RequiredScopes) == 0 {
				t.Errorf("%s declares no scopes; consent cannot be reviewed", chk.ID)
			}
			for _, s := range chk.RequiredScopes {
				if !isReadOnlyScope(s) {
					t.Errorf("%s requests %q, which is not a read-only scope", chk.ID, s)
				}
			}
		}
	}
}

// The scope classifier itself needs testing, since a wrong "read-only" verdict
// would let a write-capable scope through the gate above unnoticed.
func TestIsReadOnlyScope(t *testing.T) {
	readOnly := []string{
		"Policy.Read.All",
		"RoleManagement.Read.Directory",
		"Directory.Read.All",
		"Domain.Read.All",
		"InformationProtectionPolicy.Read.All",
		"admin.directory.user.readonly",
		"admin.directory.domain.readonly",
	}
	writeCapable := []string{
		"Policy.ReadWrite.All",
		"RoleManagement.ReadWrite.Directory",
		"Directory.ReadWrite.All",
		"admin.directory.user",
		"https://www.googleapis.com/auth/admin.directory.user",
		"Mail.Send",
	}

	for _, s := range readOnly {
		if !isReadOnlyScope(s) {
			t.Errorf("%q should be recognised as read-only", s)
		}
	}
	for _, s := range writeCapable {
		if isReadOnlyScope(s) {
			t.Errorf("%q must NOT be recognised as read-only", s)
		}
	}
}
