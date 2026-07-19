package auth

import (
	"net/url"
	"strings"
	"testing"
)

// A connector that can write is one no administrator should consent to, and the
// whole argument for granting it directory access rests on that guarantee. This
// fails the build rather than the review if a future check widens the request.
func TestScopesAreReadOnly(t *testing.T) {
	for _, s := range MicrosoftScopes {
		if s == "offline_access" {
			continue // a refresh grant, not an access grant
		}
		if !strings.HasSuffix(s, ".Read.All") && !strings.HasSuffix(s, ".Read.Directory") {
			t.Errorf("Microsoft scope %q is not read-only", s)
		}
	}
	for _, s := range GoogleScopes {
		if !strings.HasSuffix(s, ".readonly") {
			t.Errorf("Google scope %q is not read-only", s)
		}
	}
}

// The published guidance told operators to obtain a Google token with
// `gcloud auth print-access-token`, which returns a Cloud Platform token
// carrying no Admin SDK scopes — so every Google check reported "undetermined"
// regardless of how the tenant was configured. The scopes must name the Admin
// SDK explicitly.
func TestGoogleScopesTargetAdminSDK(t *testing.T) {
	for _, s := range GoogleScopes {
		if !strings.Contains(s, "admin.directory.") {
			t.Errorf("Google scope %q does not address the Admin SDK", s)
		}
	}
}

func TestBeginProducesPKCEChallenge(t *testing.T) {
	cfg, err := ForProvider("m365", "client-123", "http://127.0.0.1:5000/callback")
	if err != nil {
		t.Fatal(err)
	}
	f, raw, err := Begin(cfg)
	if err != nil {
		t.Fatal(err)
	}

	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("authorisation URL does not parse: %v", err)
	}
	q := u.Query()

	if got := q.Get("code_challenge_method"); got != "S256" {
		t.Errorf("code_challenge_method = %q, want S256", got)
	}
	// A plain challenge, or none, would let anyone who intercepts the redirect
	// exchange the authorization code themselves.
	if q.Get("code_challenge") == "" {
		t.Error("no code_challenge; the flow is not protected by PKCE")
	}
	if q.Get("client_id") != "client-123" {
		t.Errorf("client_id = %q", q.Get("client_id"))
	}
	if q.Get("state") != f.State() {
		t.Error("state in the URL does not match the flow's state")
	}
	if q.Get("state") == "" {
		t.Error("no state; the callback cannot distinguish this flow's redirect from any other")
	}
}

// Two sign-ins must not share a verifier or state, or one flow's intercepted
// redirect could be replayed against the other.
func TestBeginIsUniquePerFlow(t *testing.T) {
	cfg, _ := ForProvider("google", "id", "http://127.0.0.1:5000/callback")
	a, _, _ := Begin(cfg)
	b, _, _ := Begin(cfg)

	if a.State() == b.State() {
		t.Error("two flows produced the same state")
	}
	if a.verifier == b.verifier {
		t.Error("two flows produced the same PKCE verifier")
	}
}

func TestForProviderRejectsUnknown(t *testing.T) {
	if _, err := ForProvider("dropbox", "id", "http://127.0.0.1:1/callback"); err == nil {
		t.Error("an unknown provider was accepted")
	}
}

// Raw OAuth error codes are accurate and useless to the administrator who has
// to act on them.
func TestDescribeExplainsCommonFailures(t *testing.T) {
	for _, code := range []string{"invalid_client", "access_denied", "invalid_grant", "invalid_scope"} {
		got := describe(code, "")
		if got == code {
			t.Errorf("%s was not translated into guidance", code)
		}
		if len(got) < 30 {
			t.Errorf("%s produced %q, which does not say what to do", code, got)
		}
	}
}
