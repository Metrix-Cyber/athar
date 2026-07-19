package cloud

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// maxResponseBytes bounds how much of a response is read.
//
// A connector reading an untrusted-sized response into memory is a denial of
// service against the machine running the assessment. Directory listings can
// be large; this caps a single page rather than trusting the server.
const maxResponseBytes = 32 << 20 // 32 MiB

// APIError carries a failed API response in a form checks can interpret.
//
// The distinction matters: a 403 usually means a scope was not granted, which
// is an "undetermined" finding the administrator can fix, whereas a 404 often
// means the feature is not licensed, which is a different conversation. Both
// are materially different from "the control is not in place", and reporting
// either as a failure would be a false finding.
type APIError struct {
	Status int
	Path   string
	Body   string
}

func (e *APIError) Error() string {
	switch {
	case e.Status == http.StatusForbidden:
		return fmt.Sprintf("access denied reading %s: the required read scope has not been granted (HTTP 403)", e.Path)
	case e.Status == http.StatusUnauthorized:
		return fmt.Sprintf("authentication failed reading %s (HTTP 401)", e.Path)
	case e.Status == http.StatusNotFound:
		return fmt.Sprintf("%s is not available on this tenant, which usually means the feature is not licensed (HTTP 404)", e.Path)
	case e.Status == http.StatusTooManyRequests:
		return fmt.Sprintf("rate limited reading %s (HTTP 429)", e.Path)
	case e.Status >= 500:
		return fmt.Sprintf("provider error reading %s (HTTP %d)", e.Path, e.Status)
	}
	return fmt.Sprintf("reading %s failed (HTTP %d): %s", e.Path, e.Status, truncate(e.Body, 200))
}

// Denied reports whether the failure was a permissions problem rather than a
// finding about the tenant's configuration.
func (e *APIError) Denied() bool {
	return e.Status == http.StatusForbidden || e.Status == http.StatusUnauthorized
}

// Unavailable reports whether the resource does not exist for this tenant,
// typically an unlicensed feature.
func (e *APIError) Unavailable() bool { return e.Status == http.StatusNotFound }

func decodeResponse(resp *http.Response, path string, out any) error {
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return fmt.Errorf("reading response from %s: %w", path, err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return &APIError{Status: resp.StatusCode, Path: path, Body: string(body)}
	}
	if out == nil {
		return nil
	}
	if err := json.Unmarshal(body, out); err != nil {
		return fmt.Errorf("decoding response from %s: %w", path, err)
	}
	return nil
}

func truncate(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
