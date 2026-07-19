// Command athar-report renders Athar output as a self-contained HTML report.
//
// It accepts host scans and tenant assessments together, so one document can
// cover an entity's whole assessed estate rather than leaving an assessor to
// reconcile several.
//
// The output has no external references — no CDN, no fonts, no images — so it
// opens correctly on an air-gapped machine and can be mailed as one file.
package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/Metrix-Cyber/athar/internal/finding"
	"github.com/Metrix-Cyber/athar/internal/report"
)

var version = "dev"

func main() {
	var (
		in      = flag.String("in", "scan.json", "report file(s) to render, comma-separated. Host scans and tenant assessments can be combined.")
		out     = flag.String("out", "report.html", "HTML output path")
		org     = flag.String("org", "", "organization name shown on the report")
		brand   = flag.String("brand", "Metrix Cyber", "issuing organization")
		showVer = flag.Bool("version", false, "print version and exit")
	)
	flag.Parse()

	if *showVer {
		fmt.Printf("athar-report %s\n", version)
		return
	}

	var (
		sources  []report.Source
		findings []finding.Finding
	)
	for _, path := range strings.Split(*in, ",") {
		path = strings.TrimSpace(path)
		if path == "" {
			continue
		}
		src, fs, err := report.Load(path)
		if err != nil {
			fatal("%v", err)
		}
		sources = append(sources, src)
		findings = append(findings, fs...)
	}
	if len(sources) == 0 {
		fatal("no input files given")
	}

	f, err := os.Create(*out)
	if err != nil {
		fatal("creating %s: %v", *out, err)
	}
	defer f.Close()

	if err := report.Render(f, sources, findings, *org, *brand); err != nil {
		fatal("rendering: %v", err)
	}
	fmt.Printf("Wrote %s\n", *out)
}

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}
