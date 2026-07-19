package main

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Metrix-Cyber/athar/internal/check"
	"github.com/Metrix-Cyber/athar/internal/finding"
	"github.com/Metrix-Cyber/athar/internal/framework"
	"github.com/Metrix-Cyber/athar/internal/report"
)

// guidedMode runs the whole flow for someone who double-clicked the binary.
//
// Without this, launching Athar from a file manager prints JSON into a console
// window that closes before it can be read — which is worse than useless for
// the people the tool is meant to reach. A compliance officer is not going to
// open a terminal and chain three commands together.
//
// It deliberately does NOT open the report in a browser. Doing so would mean
// launching a process, and the scanner's guarantee that it executes no
// subprocess is worth more than saving one click: that guarantee is what lets
// it run where script execution is restricted. The path is printed instead.
func guidedMode(rep check.Report, findings []finding.Finding) {
	dir := outputDir()
	stamp := time.Now().Format("20060102-1504")
	base := sanitize(rep.Host.Hostname)

	jsonPath := filepath.Join(dir, fmt.Sprintf("athar-%s-%s.json", base, stamp))
	htmlPath := filepath.Join(dir, fmt.Sprintf("athar-%s-%s.html", base, stamp))

	if err := writeJSON(jsonPath, rep); err != nil {
		fmt.Fprintf(os.Stderr, "\nCould not write %s: %v\n", jsonPath, err)
		pause()
		os.Exit(1)
	}

	src, fs, err := report.Load(jsonPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "\nCould not read back the scan: %v\n", err)
		pause()
		os.Exit(1)
	}

	// One report per framework. A single scan is evidence against every
	// framework it can be mapped to, and which one a reader needs depends on
	// what they are accountable for — so produce them all rather than making
	// that choice for them or hiding the others behind a flag.
	type produced struct {
		name string
		path string
	}
	var written []produced

	for _, info := range framework.Available() {
		path := htmlPath
		if info.ID != framework.ECCID {
			path = strings.TrimSuffix(htmlPath, ".html") + "-" + string(info.ID) + ".html"
		}

		out, cerr := os.Create(path)
		if cerr != nil {
			fmt.Fprintf(os.Stderr, "  Could not create %s: %v\n", path, cerr)
			continue
		}
		rerr := report.Render(out, info.ID, []report.Source{src}, fs, "", "Metrix Cyber")
		out.Close()
		if rerr != nil {
			// A framework with no usable mapping is skipped rather than fatal;
			// the remaining reports are still worth having. The reason is
			// printed so a missing report is never silent.
			fmt.Fprintf(os.Stderr, "  Skipped %s: %v\n", info.Name, rerr)
			os.Remove(path)
			continue
		}
		written = append(written, produced{name: info.Name, path: path})
	}

	if len(written) == 0 {
		fmt.Fprintf(os.Stderr, "\nNo report could be produced.\n")
		pause()
		os.Exit(1)
	}

	s := rep.Summary

	fmt.Printf("\n  Athar — NCA ECC-2:2024 assessment\n")
	fmt.Printf("  %s\n\n", rep.Host.Hostname)

	fmt.Printf("  %d checks run.  %d passed, %d need attention",
		len(check.ForCurrentPlatform()), s.Pass, s.Fail)
	if s.Unknown > 0 {
		fmt.Printf(", %d could not be read", s.Unknown)
	}
	fmt.Printf(".\n")

	if s.Fail > 0 {
		var parts []string
		for _, sev := range []string{"critical", "high", "medium", "low"} {
			if n := s.BySeverity[sev]; n > 0 {
				parts = append(parts, fmt.Sprintf("%d %s", n, sev))
			}
		}
		fmt.Printf("  Severity: %s.\n", strings.Join(parts, ", "))
	}

	if !rep.Elevated {
		fmt.Printf("\n  For a complete assessment, right-click this program and choose\n")
		fmt.Printf("  'Run as administrator' — two checks need it.\n")
	}

	// Hand the finished report to the browser rather than asking the reader to
	// go and find a file. If that fails — no default handler, a locked-down
	// desktop — the path is printed instead.
	fmt.Printf("\n  Reports produced:\n")
	for _, w := range written {
		fmt.Printf("    %-48s %s\n", w.name, filepath.Base(w.path))
	}

	fmt.Printf("\n  Opening the first...\n")
	if err := openReport(written[0].path); err != nil {
		fmt.Printf("  Could not open it automatically. Open these files in any browser.\n")
	}

	fmt.Printf("\n  Saved to %s\n", filepath.Dir(htmlPath))
	fmt.Printf("  The report describes weaknesses on this machine. Treat it as\n")
	fmt.Printf("  confidential and review it before sharing.\n")

	pause()
}

// outputDir puts results beside the executable where the user can find them,
// falling back to the working directory if that location is not writable —
// which it often is not when the binary is run from Downloads or a share.
func outputDir() string {
	exe, err := os.Executable()
	if err == nil {
		dir := filepath.Dir(exe)
		if probe, err := os.CreateTemp(dir, ".athar-write-test-*"); err == nil {
			name := probe.Name()
			probe.Close()
			os.Remove(name)
			return dir
		}
	}
	if wd, err := os.Getwd(); err == nil {
		return wd
	}
	return "."
}

// sanitize makes a hostname safe for a filename.
func sanitize(s string) string {
	if s == "" {
		return "host"
	}
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_':
			b.WriteRune(r)
		default:
			b.WriteRune('-')
		}
	}
	return b.String()
}

// pause holds the console open so a user who launched from a file manager can
// read the result before the window disappears.
func pause() {
	fmt.Print("\n  Press Enter to close... ")
	bufio.NewReader(os.Stdin).ReadString('\n')
}
