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

	f, err := os.Create(htmlPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "\nCould not create %s: %v\n", htmlPath, err)
		pause()
		os.Exit(1)
	}
	err = report.Render(f, []report.Source{src}, fs, "", "Metrix Cyber")
	f.Close()
	if err != nil {
		fmt.Fprintf(os.Stderr, "\nCould not render the report: %v\n", err)
		pause()
		os.Exit(1)
	}

	s := rep.Summary
	fmt.Printf("\n%s\n", strings.Repeat("=", 62))
	fmt.Printf("  Scan complete — %d checks, %d findings\n", len(check.ForCurrentPlatform()), s.Total)
	fmt.Printf("    %d passed   %d failed   %d could not be determined\n", s.Pass, s.Fail, s.Unknown)
	if s.Fail > 0 {
		var parts []string
		for _, sev := range []string{"critical", "high", "medium", "low"} {
			if n := s.BySeverity[sev]; n > 0 {
				parts = append(parts, fmt.Sprintf("%d %s", n, sev))
			}
		}
		fmt.Printf("    Failures by severity: %s\n", strings.Join(parts, ", "))
	}
	fmt.Printf("%s\n\n", strings.Repeat("=", 62))

	fmt.Printf("  Report:  %s\n", htmlPath)
	fmt.Printf("  Data:    %s\n\n", jsonPath)
	fmt.Println("  Open the report file above in any browser to read the results.")

	if !rep.Elevated {
		fmt.Println("\n  Note: this scan ran without administrator rights, so some checks")
		fmt.Println("  could not be determined. Right-click and choose 'Run as administrator'")
		fmt.Println("  for a complete assessment.")
	}

	fmt.Println("\n  This report describes weaknesses on this machine. Treat it as")
	fmt.Println("  sensitive and review it before sharing.")

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
