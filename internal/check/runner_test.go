package check

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/Metrix-Cyber/athar/internal/finding"
)

// The runner is the safety net every check sits on. It has been credited
// repeatedly in this project for containing a crash — the BOOLEAN syscall
// defect surfaced as one undetermined finding instead of a dead scan — while
// never having been tested. These tests cover that behaviour.

func mkCheck(id string, run Func) Check {
	return Check{
		ID:           id,
		Subdomain:    "2-2",
		ControlCodes: []string{"2-2-2"},
		Platforms:    []string{"windows", "linux"},
		Run:          run,
	}
}

func passing(id string) Check {
	return mkCheck(id, func(context.Context) []finding.Finding {
		return []finding.Finding{
			finding.New(id, "ok", "2-2", []string{"2-2-2"}).Passed("fine"),
		}
	})
}

func TestPanicInOneCheckDoesNotStopTheScan(t *testing.T) {
	checks := []Check{
		passing("a"),
		mkCheck("b", func(context.Context) []finding.Finding {
			panic("simulated defect, as happened with AuditQuerySystemPolicy")
		}),
		passing("c"),
	}

	rep := Run(context.Background(), checks, HostInfo{Hostname: "test"}, false, "test")

	if len(rep.Findings) != 3 {
		t.Fatalf("got %d findings, want 3: a panicking check must not cost the others",
			len(rep.Findings))
	}
	if rep.Summary.Pass != 2 {
		t.Errorf("passing checks = %d, want 2", rep.Summary.Pass)
	}
	if rep.Summary.Unknown != 1 {
		t.Errorf("undetermined = %d, want 1 (the panic)", rep.Summary.Unknown)
	}
}

func TestPanicIsReportedAsUndeterminedNotFailure(t *testing.T) {
	// A crashed check tells us nothing about the host. Recording it as a
	// failure would assert a control is not met on no evidence at all.
	checks := []Check{mkCheck("boom", func(context.Context) []finding.Finding {
		panic("kaboom")
	})}

	rep := Run(context.Background(), checks, HostInfo{}, false, "test")

	f := rep.Findings[0]
	if f.Status != finding.Unknown {
		t.Errorf("status = %q, want unknown", f.Status)
	}
	if f.Err == "" {
		t.Error("the panic reason must be recorded, or the failure is undiagnosable")
	}
	if !strings.Contains(f.Err, "kaboom") {
		t.Errorf("error should carry the panic value, got %q", f.Err)
	}
}

func TestCancelledContextSkipsRemainingChecks(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	rep := Run(ctx, []Check{passing("a"), passing("b")}, HostInfo{}, false, "test")

	if rep.Summary.Unknown != 2 {
		t.Errorf("undetermined = %d, want 2: a cancelled scan must not report passes",
			rep.Summary.Unknown)
	}
	if rep.Summary.Pass != 0 {
		t.Errorf("a cancelled scan reported %d passes; it examined nothing", rep.Summary.Pass)
	}
}

func TestSummaryCountsEachStatus(t *testing.T) {
	checks := []Check{
		mkCheck("multi", func(context.Context) []finding.Finding {
			n := func(id string) finding.Finding {
				return finding.New(id, id, "2-5", []string{"2-5-2"})
			}
			return []finding.Finding{
				n("p").Passed("ok"),
				n("f1").Failed(finding.Critical, "bad", "fix"),
				n("f2").Failed(finding.Medium, "bad", "fix"),
				n("u").Undetermined(context.Canceled),
				n("na").Inapplicable("not relevant"),
			}
		}),
	}

	s := Run(context.Background(), checks, HostInfo{}, false, "test").Summary

	if s.Total != 5 || s.Pass != 1 || s.Fail != 2 || s.Unknown != 1 || s.NotApplicable != 1 {
		t.Errorf("summary = %+v; want 5 total / 1 pass / 2 fail / 1 unknown / 1 n-a", s)
	}
	if s.BySeverity["critical"] != 1 || s.BySeverity["medium"] != 1 {
		t.Errorf("severity counts = %v, want one critical and one medium", s.BySeverity)
	}
	// Only failures carry severity; a pass must not inflate the counts.
	if s.BySeverity["info"] != 0 {
		t.Errorf("passing findings must not appear in severity counts, got %v", s.BySeverity)
	}
}

func TestSubdomainsCoveredDeduplicates(t *testing.T) {
	// Several checks touch the same subdomain. Counting it twice would
	// overstate coverage, which is the number an assessor reads first.
	checks := []Check{
		mkCheck("a", func(context.Context) []finding.Finding {
			return []finding.Finding{finding.New("a", "a", "2-2", nil).Passed("ok")}
		}),
		mkCheck("b", func(context.Context) []finding.Finding {
			return []finding.Finding{finding.New("b", "b", "2-2", nil).Passed("ok")}
		}),
		mkCheck("c", func(context.Context) []finding.Finding {
			return []finding.Finding{finding.New("c", "c", "2-5", nil).Passed("ok")}
		}),
	}

	s := Run(context.Background(), checks, HostInfo{}, false, "test").Summary
	if len(s.SubdomainsCovered) != 2 {
		t.Errorf("subdomains covered = %v, want 2 distinct", s.SubdomainsCovered)
	}
}

func TestClausesCitedCountsDistinctCodes(t *testing.T) {
	// Clause coverage is the honest measure stated in the report. Counting a
	// clause once per citing check would inflate it.
	checks := []Check{
		{ID: "a", Subdomain: "2-2", ControlCodes: []string{"2-2-2", "2-2-3-1"},
			Platforms: []string{"windows", "linux"}, Run: func(context.Context) []finding.Finding { return nil }},
		{ID: "b", Subdomain: "2-2", ControlCodes: []string{"2-2-2"},
			Platforms: []string{"windows", "linux"}, Run: func(context.Context) []finding.Finding { return nil }},
	}

	rep := Run(context.Background(), checks, HostInfo{}, false, "test")
	if rep.Summary.ClausesCited != 2 {
		t.Errorf("clauses cited = %d, want 2 distinct (2-2-2 counted once)",
			rep.Summary.ClausesCited)
	}
}

func TestReportCarriesDigestAndTiming(t *testing.T) {
	rep := Run(context.Background(), []Check{passing("a")}, HostInfo{}, true, "v1.2.3")

	if rep.FindingsDigest == "" {
		t.Error("report has no findings digest")
	}
	if rep.ScannerVersion != "v1.2.3" {
		t.Errorf("scanner version = %q, want v1.2.3", rep.ScannerVersion)
	}
	if !rep.Elevated {
		t.Error("elevation flag not carried into the report")
	}
	if rep.FinishedAt.Before(rep.StartedAt) {
		t.Error("finished before it started")
	}
	if time.Since(rep.FinishedAt) > time.Minute {
		t.Error("finish timestamp is not recent")
	}
}

func TestRegistryFiltersByPlatform(t *testing.T) {
	// Registration is global, so this test uses IDs unlikely to collide.
	Register(Check{ID: "test.only.windows", Subdomain: "2-2",
		ControlCodes: []string{"2-2-2"}, Platforms: []string{"windows"},
		Run: func(context.Context) []finding.Finding { return nil }})
	Register(Check{ID: "test.only.linux", Subdomain: "2-2",
		ControlCodes: []string{"2-2-2"}, Platforms: []string{"linux"},
		Run: func(context.Context) []finding.Finding { return nil }})

	var sawWindows, sawLinux bool
	for _, c := range ForCurrentPlatform() {
		switch c.ID {
		case "test.only.windows":
			sawWindows = true
		case "test.only.linux":
			sawLinux = true
		}
	}
	if sawWindows == sawLinux {
		t.Error("exactly one platform-specific check should be selected for this host")
	}

	// All() ignores platform, so both must appear.
	var count int
	for _, c := range All() {
		if strings.HasPrefix(c.ID, "test.only.") {
			count++
		}
	}
	if count != 2 {
		t.Errorf("All() returned %d test checks, want both regardless of platform", count)
	}
}

func TestDuplicateRegistrationPanics(t *testing.T) {
	// A duplicate ID can only be a programming error, and silently dropping
	// one would remove a check from every scan without trace.
	defer func() {
		if recover() == nil {
			t.Error("registering a duplicate check ID should panic")
		}
	}()
	c := Check{ID: "test.duplicate", Subdomain: "2-2", ControlCodes: []string{"2-2-2"},
		Platforms: []string{"windows", "linux"},
		Run:       func(context.Context) []finding.Finding { return nil }}
	Register(c)
	Register(c)
}
