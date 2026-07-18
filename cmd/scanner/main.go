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
	)
	flag.Parse()

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

	data, err := json.MarshalIndent(rep, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "encoding report: %v\n", err)
		os.Exit(1)
	}

	if *outPath == "" {
		fmt.Println(string(data))
	} else if err := os.WriteFile(*outPath, data, 0o600); err != nil {
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
