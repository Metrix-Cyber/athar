// Package cloud assesses SaaS tenants against ECC controls that a host scan
// cannot reach — email protection, identity policy, audit retention and
// tenant-level data protection.
//
// This is deliberately a separate component from the host scanner, and ships
// as a separate binary. The scanner's value rests on being offline,
// credential-free and read-only; a connector is none of those things by
// necessity. Merging them would trade away the property that makes the scanner
// runnable inside a regulated environment in the first place.
//
// Everything here is read-only. Providers must request read scopes only, and
// no credential is ever written to disk or included in output.
package cloud

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/Metrix-Cyber/athar/internal/finding"
)

// Provider is one assessable SaaS tenant.
type Provider interface {
	// Name identifies the provider in output, e.g. "microsoft-365".
	Name() string
	// Checks returns the checks this provider can run.
	Checks() []Check
}

// Check is one tenant-level assessment.
type Check struct {
	// ID is namespaced by provider: "m365.email.antiphishing".
	ID string
	// Subdomain is the ECC-2:2024 subdomain, e.g. "2-4".
	Subdomain string
	// ControlCodes are the clauses this check provides evidence toward.
	ControlCodes []string
	// RequiredScopes documents the API permissions the check needs, so an
	// administrator granting consent can see exactly what is being asked for
	// and why. Anything beyond read access is a bug.
	RequiredScopes []string
	Run            func(ctx context.Context, c *Client) []finding.Finding
}

// Client performs authenticated read-only API calls.
//
// The HTTP client is injectable so provider logic can be exercised against
// recorded responses in tests. That is not a convenience: without a live
// tenant to test against, fixture-driven tests are the only verification this
// code gets before it runs against a customer's directory.
type Client struct {
	HTTP    *http.Client
	BaseURL string
	// Token returns a bearer token. It is a function rather than a value so
	// credentials stay out of struct dumps and logs, and so refresh is
	// possible without the caller holding the secret.
	Token func(ctx context.Context) (string, error)
}

// Get performs a read-only request and decodes the JSON response.
//
// Only GET is exposed. A connector that cannot issue a write is one an
// administrator can grant consent to without auditing every code path.
func (c *Client) Get(ctx context.Context, path string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.BaseURL+path, nil)
	if err != nil {
		return err
	}

	tok, err := c.Token(ctx)
	if err != nil {
		return fmt.Errorf("acquiring token: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Accept", "application/json")

	client := c.HTTP
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	return decodeResponse(resp, path, out)
}

// Report is the output of a tenant assessment.
type Report struct {
	SchemaVersion  string            `json:"schema_version"`
	Provider       string            `json:"provider"`
	Tenant         string            `json:"tenant"`
	Framework      string            `json:"framework"`
	FindingsDigest string            `json:"findings_digest"`
	StartedAt      time.Time         `json:"started_at"`
	FinishedAt     time.Time         `json:"finished_at"`
	Findings       []finding.Finding `json:"findings"`
}

// Run executes checks and collects findings, containing per-check failures so
// one unavailable API does not cost the whole assessment.
func Run(ctx context.Context, p Provider, c *Client, tenant string) Report {
	rep := Report{
		SchemaVersion: "1.0",
		Provider:      p.Name(),
		Tenant:        tenant,
		Framework:     "NCA ECC-2:2024",
		StartedAt:     time.Now().UTC(),
	}

	for _, chk := range p.Checks() {
		rep.Findings = append(rep.Findings, runOne(ctx, chk, c)...)
	}

	rep.FinishedAt = time.Now().UTC()
	rep.FindingsDigest = finding.Digest(rep.Findings)
	return rep
}

func runOne(ctx context.Context, chk Check, c *Client) (out []finding.Finding) {
	defer func() {
		if r := recover(); r != nil {
			f := finding.New(chk.ID, "Check failed to execute", chk.Subdomain, chk.ControlCodes)
			out = []finding.Finding{f.Undetermined(fmt.Errorf("panic: %v", r))}
		}
	}()
	return chk.Run(ctx, c)
}
