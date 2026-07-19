// Package auth performs interactive sign-in on behalf of someone who should
// not have to obtain an access token by hand.
//
// The connector previously required the operator to produce a bearer token
// themselves — through the Azure CLI, gcloud, or an OAuth flow of their own —
// and pass it in an environment variable. That is a reasonable interface for a
// pipeline and an unreasonable one for the person the tool is actually for: a
// compliance officer with an administrator account and no interest in learning
// a cloud CLI. It also did not work as documented. The suggested gcloud command
// returns a Cloud Platform token carrying no Admin SDK scopes at all, so every
// Google check would have reported "undetermined" no matter how the tenant was
// configured.
//
// This implements the authorization code flow with PKCE against a loopback
// redirect, which is what RFC 8252 prescribes for a native application. Two
// properties matter here:
//
//   - No client secret. A secret shipped inside a downloadable binary is not a
//     secret, and PKCE removes the need for one.
//   - The credential never touches disk. The token lives in memory for the
//     duration of one assessment and is discarded with the process. Nothing is
//     cached, so a stolen machine yields no tenant access.
//
// The device authorization grant would avoid the loopback listener, but Google
// restricts that flow to a scope allowlist that excludes the Admin SDK — the
// exact scopes this tool needs. Loopback works for both providers.
package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Config describes one provider's OAuth endpoints and the access being asked
// for.
type Config struct {
	// ClientID identifies the application registration. It is not a secret:
	// it appears in the browser's address bar during sign-in.
	ClientID string
	AuthURL  string
	TokenURL string
	// Scopes are the permissions requested. Every scope here must be read-only;
	// a test enforces that, because a connector that can write is one no
	// administrator should consent to.
	Scopes []string
	// RedirectURI is the loopback address the provider returns the user to.
	RedirectURI string
}

// Flow is one in-progress sign-in.
//
// The verifier is held in memory and never logged. It is the only thing
// preventing an attacker who intercepts the redirect from exchanging the
// authorization code themselves.
type Flow struct {
	cfg      Config
	verifier string
	state    string
}

// Begin creates a sign-in flow and returns it alongside the URL the user must
// visit.
func Begin(cfg Config) (*Flow, string, error) {
	verifier, err := randomURLSafe(64)
	if err != nil {
		return nil, "", fmt.Errorf("generating PKCE verifier: %w", err)
	}
	state, err := randomURLSafe(24)
	if err != nil {
		return nil, "", fmt.Errorf("generating state: %w", err)
	}

	sum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])

	q := url.Values{
		"client_id":             {cfg.ClientID},
		"response_type":         {"code"},
		"redirect_uri":          {cfg.RedirectURI},
		"scope":                 {strings.Join(cfg.Scopes, " ")},
		"state":                 {state},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
		// Ask for a refresh token on Google and force the consent screen so an
		// administrator sees exactly which read permissions are being granted
		// rather than having a previous consent silently reused.
		"access_type": {"offline"},
		"prompt":      {"consent"},
	}

	f := &Flow{cfg: cfg, verifier: verifier, state: state}
	return f, cfg.AuthURL + "?" + q.Encode(), nil
}

// State returns the opaque value the provider will echo back, so the callback
// handler can reject a response that did not originate from this flow.
func (f *Flow) State() string { return f.state }

// Token is an access token and its lifetime.
type Token struct {
	AccessToken string
	ExpiresAt   time.Time
}

// Expired reports whether the token is at or near the end of its life. The
// margin avoids handing back a token that expires mid-assessment.
func (t Token) Expired() bool {
	return time.Now().After(t.ExpiresAt.Add(-2 * time.Minute))
}

// Exchange trades an authorization code for an access token.
func (f *Flow) Exchange(ctx context.Context, code string) (Token, error) {
	form := url.Values{
		"client_id":     {f.cfg.ClientID},
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {f.cfg.RedirectURI},
		"code_verifier": {f.verifier},
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, f.cfg.TokenURL,
		strings.NewReader(form.Encode()))
	if err != nil {
		return Token{}, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := (&http.Client{Timeout: 30 * time.Second}).Do(req)
	if err != nil {
		return Token{}, err
	}
	defer resp.Body.Close()

	var body struct {
		AccessToken      string `json:"access_token"`
		ExpiresIn        int    `json:"expires_in"`
		Error            string `json:"error"`
		ErrorDescription string `json:"error_description"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return Token{}, fmt.Errorf("decoding token response: %w", err)
	}

	if body.Error != "" {
		return Token{}, fmt.Errorf("sign-in failed: %s", describe(body.Error, body.ErrorDescription))
	}
	if body.AccessToken == "" {
		return Token{}, fmt.Errorf("the provider returned no access token")
	}

	// Default to a conservative lifetime when the provider omits one, so an
	// assessment fails with a clear authentication error rather than partway
	// through with confusing per-check denials.
	life := time.Duration(body.ExpiresIn) * time.Second
	if life == 0 {
		life = 30 * time.Minute
	}
	return Token{AccessToken: body.AccessToken, ExpiresAt: time.Now().Add(life)}, nil
}

// describe turns an OAuth error code into something an administrator can act
// on. The raw codes are accurate and useless: "invalid_client" does not tell
// anyone that they pasted the wrong application ID.
func describe(code, detail string) string {
	switch code {
	case "invalid_client", "unauthorized_client":
		return "the application ID was not accepted by the provider. Check that it was copied correctly and that the app registration allows public client sign-in."
	case "access_denied":
		return "consent was declined, or an administrator has restricted which applications may be granted these permissions."
	case "invalid_grant":
		return "the sign-in expired before it completed. Start again."
	case "invalid_scope":
		return "the app registration does not list one of the required read permissions. Add them and grant admin consent."
	}
	if detail != "" {
		return detail
	}
	return code
}

// randomURLSafe returns n bytes of cryptographic randomness, URL-safe encoded.
func randomURLSafe(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
