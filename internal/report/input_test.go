package report

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Metrix-Cyber/athar/internal/finding"
)

// Load decides how a report describes what was assessed and whether that
// assessment was complete. A source wrongly marked complete makes a partial
// report look like a full one, which is the same false-completeness failure
// the checks themselves guard against.

func write(t *testing.T, name, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

const hostScan = `{
  "schema_version": "1.0",
  "framework": "NCA ECC-2:2024",
  "elevated": true,
  "host": {"hostname":"SRV01","os":"windows","os_version":"10.0.20348",
           "edition":"ServerStandard","management":{"mode":"domain","domain_joined":true}},
  "finished_at": "2026-07-19T10:00:00Z",
  "findings": [
    {"check_id":"a","subdomain":"2-2","status":"pass","severity":"info","detail":"ok"}
  ]
}`

const tenantScan = `{
  "schema_version": "1.0",
  "provider": "microsoft-365",
  "tenant": "contoso.onmicrosoft.com",
  "framework": "NCA ECC-2:2024",
  "finished_at": "2026-07-19T10:05:00Z",
  "findings": [
    {"check_id":"m","subdomain":"2-4","status":"fail","severity":"high","detail":"no"}
  ]
}`

func TestLoadClassifiesHostScan(t *testing.T) {
	src, fs, err := Load(write(t, "h.json", hostScan))
	if err != nil {
		t.Fatal(err)
	}
	if src.Kind != "host" {
		t.Errorf("kind = %q, want host", src.Kind)
	}
	if src.Name != "SRV01" {
		t.Errorf("name = %q, want SRV01", src.Name)
	}
	if src.Management == nil || src.Management.Mode != "domain" {
		t.Error("management mode not carried through; remediation guidance depends on it")
	}
	if src.Partial {
		t.Error("an elevated scan with no undetermined findings is complete, not partial")
	}
	if len(fs) != 1 {
		t.Errorf("findings = %d, want 1", len(fs))
	}
}

func TestLoadClassifiesTenantAssessment(t *testing.T) {
	src, _, err := Load(write(t, "t.json", tenantScan))
	if err != nil {
		t.Fatal(err)
	}
	if src.Kind != "tenant" {
		t.Errorf("kind = %q, want tenant", src.Kind)
	}
	if src.Name != "contoso.onmicrosoft.com" {
		t.Errorf("name = %q", src.Name)
	}
	if src.Detail != "Microsoft 365" {
		t.Errorf("detail = %q, want the provider label", src.Detail)
	}
	// A tenant has no host management mode; guidance must not be offered.
	if src.Management != nil {
		t.Error("tenant source carries a management mode it cannot have")
	}
}

func TestUnelevatedHostScanIsPartial(t *testing.T) {
	// Without elevation some checks cannot be read. Reporting that source as
	// complete would make a partial assessment indistinguishable from a full
	// one.
	scan := `{"host":{"hostname":"PC","os":"windows"},"elevated":false,
	          "findings":[{"check_id":"a","subdomain":"2-2","status":"pass"}]}`
	src, _, err := Load(write(t, "u.json", scan))
	if err != nil {
		t.Fatal(err)
	}
	if !src.Partial {
		t.Error("an unelevated host scan must be marked partial")
	}
}

func TestUndeterminedFindingMakesSourcePartial(t *testing.T) {
	scan := `{"provider":"google-workspace","tenant":"example.sa",
	          "findings":[{"check_id":"a","subdomain":"2-2","status":"unknown","error":"scope denied"}]}`
	src, _, err := Load(write(t, "p.json", scan))
	if err != nil {
		t.Fatal(err)
	}
	if !src.Partial {
		t.Error("a source with an undetermined finding must be marked partial")
	}
}

func TestLoadStripsByteOrderMark(t *testing.T) {
	// Athar never writes a BOM, but a file that has been through a Windows
	// editor or PowerShell redirection often carries one, and the raw JSON
	// error tells a user nothing about what is wrong.
	src, _, err := Load(write(t, "bom.json", "\ufeff"+hostScan))
	if err != nil {
		t.Fatalf("a BOM-prefixed report failed to load: %v", err)
	}
	if src.Name != "SRV01" {
		t.Errorf("name = %q after BOM strip", src.Name)
	}
}

func TestLoadRejectsUnrelatedJSON(t *testing.T) {
	// Rendering an unrelated file as an empty report would produce a
	// professional-looking document asserting nothing was wrong.
	_, _, err := Load(write(t, "x.json", `{"hello":"world"}`))
	if err == nil {
		t.Fatal("a file that is not an Athar report was accepted")
	}
}

func TestLoadReportsMissingFile(t *testing.T) {
	if _, _, err := Load(filepath.Join(t.TempDir(), "absent.json")); err == nil {
		t.Error("a missing file should produce an error")
	}
}

func TestSummarizeRecomputesAcrossSources(t *testing.T) {
	// A combined report is scored as one assessment. Carrying a per-source
	// summary through would double-count or under-count.
	n := func(id, sub string) finding.Finding {
		return finding.New(id, id, sub, []string{"2-2-2"})
	}
	fs := []finding.Finding{
		n("a", "2-2").Passed("ok"),
		n("b", "2-4").Failed(finding.Critical, "bad", "fix"),
		n("c", "2-4").Failed(finding.Low, "bad", "fix"),
		n("d", "2-5").Undetermined(nil),
		n("e", "2-5").Inapplicable("n/a"),
	}

	s := summarize(fs)
	if s.Total != 5 || s.Pass != 1 || s.Fail != 2 || s.Unknown != 1 || s.NotApplicable != 1 {
		t.Errorf("summary = %+v", s)
	}
	if len(s.SubdomainsCovered) != 3 {
		t.Errorf("subdomains = %v, want 3 distinct", s.SubdomainsCovered)
	}
	if s.BySeverity["critical"] != 1 || s.BySeverity["low"] != 1 {
		t.Errorf("severity counts = %v", s.BySeverity)
	}
}

func TestProviderLabels(t *testing.T) {
	for in, want := range map[string]string{
		"microsoft-365":    "Microsoft 365",
		"google-workspace": "Google Workspace",
		"something-else":   "something-else",
	} {
		if got := providerLabel(in); got != want {
			t.Errorf("providerLabel(%q) = %q, want %q", in, got, want)
		}
	}
}
