package main

import (
	"context"
	"fmt"
	"html/template"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Metrix-Cyber/athar/internal/check"
	"github.com/Metrix-Cyber/athar/internal/finding"
	"github.com/Metrix-Cyber/athar/internal/framework"
	"github.com/Metrix-Cyber/athar/internal/report"
)

// Guided mode gave someone who double-clicked the binary a console window with
// a few lines of text in it. That is a shell tool wearing a hat: it still asks
// the reader to accept a terminal, still hides the findings behind "open this
// file yourself", and looks nothing like a product anyone would pay for.
//
// This serves the scan as a page instead. The binary is double-clicked, a
// browser opens, one button runs the scan, and the findings appear as a
// dashboard that can be read, filtered and exported.
//
// The listener binds to 127.0.0.1. A page enumerating a host's security
// weaknesses must not be reachable from the network, and binding to a routable
// address would publish exactly that.

type uiServer struct {
	mux     *http.ServeMux
	base    string
	version string

	mu     sync.Mutex
	report *check.Report
	files  map[string]string // framework ID -> written HTML path
	json   string

	done chan struct{}
}

func runUI(version string) error {
	// Port zero lets the OS pick a free port, so the program never collides
	// with whatever else the machine happens to be running.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return fmt.Errorf("starting the interface: %w", err)
	}

	s := &uiServer{
		mux:     http.NewServeMux(),
		base:    fmt.Sprintf("http://127.0.0.1:%d", ln.Addr().(*net.TCPAddr).Port),
		version: version,
		files:   map[string]string{},
		done:    make(chan struct{}),
	}
	s.routes()

	srv := &http.Server{Handler: s.mux, ReadHeaderTimeout: 10 * time.Second}
	go func() { _ = srv.Serve(ln) }()

	fmt.Printf("\n  Athar — opening %s\n", s.base)
	fmt.Printf("  If your browser does not open, paste that address into it.\n\n")
	if err := openReport(s.base); err != nil {
		fmt.Printf("  Could not open a browser automatically.\n")
	}

	<-s.done
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_ = srv.Shutdown(ctx)
	return nil
}

func (s *uiServer) routes() {
	s.mux.HandleFunc("/", s.handleHome)
	s.mux.HandleFunc("/scan", s.handleScan)
	s.mux.HandleFunc("/report", s.handleReport)
	s.mux.HandleFunc("/quit", s.handleQuit)
}

func (s *uiServer) handleHome(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}

	s.mu.Lock()
	rep := s.report
	s.mu.Unlock()

	if rep == nil {
		host, _ := os.Hostname()
		renderUI(w, pageReady, map[string]any{
			"Host":     host,
			"Checks":   len(check.ForCurrentPlatform()),
			"Elevated": isElevated(),
			"Version":  s.version,
		})
		return
	}
	s.renderResults(w, rep)
}

// handleScan runs the checks. It is a POST because it does work; a GET that
// scanned would run again on every refresh.
func (s *uiServer) handleScan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Minute)
	defer cancel()

	checks := check.ForCurrentPlatform()
	rep := check.Run(ctx, checks, hostInfo(), isElevated(), s.version)
	_, rep.Summary.ClausesTotal = framework.ECC().ClauseCoverage(check.ControlRefs())

	s.mu.Lock()
	s.report = &rep
	s.mu.Unlock()

	s.writeArtifacts(rep)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// writeArtifacts saves the machine-readable scan and one rendered report per
// framework, so the findings on screen can be handed to someone else exactly as
// they appear.
func (s *uiServer) writeArtifacts(rep check.Report) {
	dir := uiOutputDir()
	stamp := rep.StartedAt.Format("20060102-1504")
	base := sanitize(rep.Host.Hostname)

	jsonPath := filepath.Join(dir, fmt.Sprintf("athar-%s-%s.json", base, stamp))
	if err := writeJSON(jsonPath, rep); err != nil {
		return
	}

	s.mu.Lock()
	s.json = jsonPath
	s.mu.Unlock()

	src, fs, err := report.Load(jsonPath)
	if err != nil {
		return
	}

	for _, info := range framework.Available() {
		path := filepath.Join(dir,
			fmt.Sprintf("athar-%s-%s-%s.html", base, stamp, info.ID))
		f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
		if err != nil {
			continue
		}
		err = report.Render(f, info.ID, []report.Source{src}, fs, "", "Metrix Cyber")
		f.Close()
		if err != nil {
			// A framework with no usable mapping is skipped rather than fatal;
			// the others are still worth having.
			os.Remove(path)
			continue
		}
		s.mu.Lock()
		s.files[string(info.ID)] = path
		s.mu.Unlock()
	}
}

// handleReport serves a rendered report inline, so reading it is a click rather
// than a hunt through a folder.
func (s *uiServer) handleReport(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("framework")

	s.mu.Lock()
	path, ok := s.files[id]
	s.mu.Unlock()

	if !ok {
		http.NotFound(w, r)
		return
	}
	// Only paths this process wrote are ever served, so the query parameter
	// cannot be used to read arbitrary files.
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	http.ServeFile(w, r, path)
}

func (s *uiServer) handleQuit(w http.ResponseWriter, r *http.Request) {
	renderUI(w, pageClosedScan, nil)
	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}
	select {
	case <-s.done:
	default:
		close(s.done)
	}
}

// row is one finding prepared for display.
type row struct {
	finding.Finding
	Codes     string
	Subdomain string
}

func (s *uiServer) renderResults(w http.ResponseWriter, rep *check.Report) {
	cat := framework.ECC()

	// Failures first, most severe first, so the reader sees what matters
	// without scrolling. A list sorted by check ID buries a critical finding
	// among passes.
	order := map[string]int{"critical": 0, "high": 1, "medium": 2, "low": 3}
	fs := append([]finding.Finding(nil), rep.Findings...)
	sort.SliceStable(fs, func(i, j int) bool {
		si, sj := statusRank(fs[i]), statusRank(fs[j])
		if si != sj {
			return si < sj
		}
		return order[strings.ToLower(string(fs[i].Severity))] <
			order[strings.ToLower(string(fs[j].Severity))]
	})

	var failed, passed, undetermined []row
	for _, f := range fs {
		r := row{
			Finding:   f,
			Codes:     strings.Join(f.ControlCodes, ", "),
			Subdomain: cat.SubdomainTitle(f.Subdomain),
		}
		switch string(f.Status) {
		case "fail":
			failed = append(failed, r)
		case "pass":
			passed = append(passed, r)
		default:
			undetermined = append(undetermined, r)
		}
	}

	s.mu.Lock()
	reports := make([]map[string]string, 0, len(s.files))
	for _, info := range framework.Available() {
		if _, ok := s.files[string(info.ID)]; ok {
			reports = append(reports, map[string]string{
				"ID": string(info.ID), "Name": info.Name,
			})
		}
	}
	dir := filepath.Dir(s.json)
	s.mu.Unlock()

	sum := rep.Summary
	renderUI(w, pageResults, map[string]any{
		"Host":         rep.Host.Hostname,
		"OS":           strings.TrimSpace(rep.Host.Edition + " " + rep.Host.Version),
		"Elevated":     rep.Elevated,
		"Duration":     rep.FinishedAt.Sub(rep.StartedAt).Round(time.Millisecond).String(),
		"Summary":      sum,
		"Critical":     sum.BySeverity["critical"],
		"High":         sum.BySeverity["high"],
		"Medium":       sum.BySeverity["medium"],
		"Low":          sum.BySeverity["low"],
		"Failed":       failed,
		"Passed":       passed,
		"Undetermined": undetermined,
		"Reports":      reports,
		"Dir":          dir,
		"Coverage":     coveragePercent(sum),
	})
}

func statusRank(f finding.Finding) int {
	switch string(f.Status) {
	case "fail":
		return 0
	case "unknown":
		return 1
	}
	return 2
}

func coveragePercent(s check.Summary) int {
	if s.ClausesTotal == 0 {
		return 0
	}
	return s.ClausesCited * 100 / s.ClausesTotal
}

func uiOutputDir() string {
	if exe, err := os.Executable(); err == nil {
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

// renderUI writes a page with a policy that forbids loading anything external,
// which is both a defence and a statement: this interface has no dependencies
// it could be compromised through.
func renderUI(w http.ResponseWriter, t *template.Template, data any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'")
	w.Header().Set("Referrer-Policy", "no-referrer")
	if err := t.Execute(w, data); err != nil {
		fmt.Fprintf(os.Stderr, "rendering page: %v\n", err)
	}
}

// sanitize makes a hostname safe to use in a filename.
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
