// Command scanner runs read-only compliance checks against the local host and
// emits structured findings as JSON.
//
// It makes no network calls and modifies nothing on the host. Report rendering
// is deliberately a separate concern: this binary produces data.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"time"

	"github.com/Metrix-Cyber/athar/internal/check"
	"github.com/Metrix-Cyber/athar/internal/framework"

	// Check packages register themselves via init(). Each is constrained by
	// build tag, so only the target platform's checks are compiled in.
	_ "github.com/Metrix-Cyber/athar/internal/checks/linux"
	_ "github.com/Metrix-Cyber/athar/internal/checks/windows"
)

// version is set at build time via -ldflags "-X main.version=...".
var version = "dev"

func main() {
	var (
		outPath = flag.String("out", "", "write JSON report to this file (default: stdout)")
		list    = flag.Bool("list", false, "list registered checks and exit")
		timeout = flag.Duration("timeout", 5*time.Minute, "overall scan timeout")
		showVer = flag.Bool("version", false, "print version and exit")
		failOn  = flag.String("fail-on", "", "exit non-zero if a finding of this severity or higher is present: critical, high, medium, low")
	)
	flag.Parse()

	// Guided mode is for someone who launched the binary from a file manager.
	// Both conditions are required: no arguments alone is not enough, because
	// `athar.exe > scan.json` has none either, and treating that as a
	// double-click silently produced an empty file instead of a report.
	guided := len(os.Args) == 1 && launchedByDoubleClick()

	if *showVer {
		fmt.Printf("athar %s\n", version)
		return
	}

	// Fail fast on a bad control mapping. A finding citing a control code that
	// does not exist — or that says something other than what was verified —
	// is the most damaging defect this product can ship, because the reader is
	// an assessor who will check.
	if err := framework.ECC().Validate(check.ControlRefs()); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}

	if *list {
		listChecks()
		return
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()
	ctx, cancelTimeout := context.WithTimeout(ctx, *timeout)
	defer cancelTimeout()

	checks := check.ForCurrentPlatform()
	if len(checks) == 0 {
		fmt.Fprintf(os.Stderr, "no checks are compiled in for %s\n", runtime.GOOS)
		os.Exit(1)
	}

	fmt.Fprintf(os.Stderr, "Running %d checks on %s/%s...\n", len(checks), runtime.GOOS, runtime.GOARCH)

	rep := check.Run(ctx, checks, hostInfo(), isElevated(), version)
	_, rep.Summary.ClausesTotal = framework.ECC().ClauseCoverage(check.ControlRefs())

	// A double-clicked launch gets the whole flow — scan, report, and a
	// console that stays open — rather than JSON in a window that closes.
	if guided {
		guidedMode(rep, rep.Findings)
		return
	}

	if *outPath == "" {
		data, err := json.MarshalIndent(rep, "", "  ")
		if err != nil {
			fmt.Fprintf(os.Stderr, "encoding report: %v\n", err)
			os.Exit(1)
		}
		fmt.Println(string(data))
	} else if err := writeJSON(*outPath, rep); err != nil {
		fmt.Fprintf(os.Stderr, "writing %s: %v\n", *outPath, err)
		os.Exit(1)
	}

	s := rep.Summary
	fmt.Fprintf(os.Stderr,
		"\nDone in %s — %d findings: %d pass, %d fail, %d undetermined.\n",
		rep.FinishedAt.Sub(rep.StartedAt).Round(time.Millisecond),
		s.Total, s.Pass, s.Fail, s.Unknown)
	if !rep.Elevated {
		fmt.Fprintln(os.Stderr,
			"Note: not running elevated — some checks could not be fully determined.")
	}

	// A scan that completed successfully exits 0 by default, even with
	// failing findings: the scan itself worked. --fail-on lets a pipeline gate
	// on results instead, which is opt-in so that adding it later cannot
	// silently break an existing automation.
	if code := failExitCode(*failOn, s); code != 0 {
		fmt.Fprintf(os.Stderr,
			"Exiting %d: findings at or above severity %q are present.\n", code, *failOn)
		os.Exit(code)
	}
}

// severityRank orders severities from most to least serious.
var severityRank = map[string]int{"critical": 0, "high": 1, "medium": 2, "low": 3}

// failExitCode returns 1 when the report contains a finding at or above the
// requested severity, and 0 otherwise. An unrecognised threshold is ignored
// rather than failing the scan, so a typo in a pipeline definition does not
// look like a compliance failure.
func failExitCode(threshold string, s check.Summary) int {
	if threshold == "" {
		return 0
	}
	limit, ok := severityRank[strings.ToLower(threshold)]
	if !ok {
		fmt.Fprintf(os.Stderr,
			"Ignoring unrecognised -fail-on value %q; expected critical, high, medium or low.\n",
			threshold)
		return 0
	}
	for name, rank := range severityRank {
		if rank <= limit && s.BySeverity[name] > 0 {
			return 1
		}
	}
	return 0
}

func listChecks() {
	cat := framework.ECC()
	for _, c := range check.All() {
		fmt.Printf("%-32s  %-5s %-42s  %v\n",
			c.ID, c.Subdomain, cat.SubdomainTitle(c.Subdomain), c.ControlCodes)
	}
	fmt.Printf("\n%d checks covering %d of %d ECC-2:2024 subdomains.\n",
		len(check.All()), countSubdomains(), cat.TotalSubdomains())
}

func countSubdomains() int {
	seen := map[string]bool{}
	for _, c := range check.All() {
		seen[c.Subdomain] = true
	}
	return len(seen)
}

func hostInfo() check.HostInfo {
	name, err := os.Hostname()
	if err != nil {
		name = "unknown"
	}
	ed := edition()
	return check.HostInfo{
		Hostname:   name,
		OS:         runtime.GOOS,
		Arch:       runtime.GOARCH,
		Version:    osVersion(),
		Edition:    ed,
		Management: management(ed),
	}
}

// writeJSON writes a report with restrictive permissions: it describes the
// weaknesses of the host it came from and should not be world-readable.
func writeJSON(path string, rep check.Report) error {
	data, err := json.MarshalIndent(rep, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o600)
}
