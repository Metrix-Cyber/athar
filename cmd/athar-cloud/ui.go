package main

import (
	"context"
	"encoding/json"
	"fmt"
	"html/template"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Metrix-Cyber/athar/internal/cloud"
	"github.com/Metrix-Cyber/athar/internal/cloud/auth"
	"github.com/Metrix-Cyber/athar/internal/cloud/google"
	"github.com/Metrix-Cyber/athar/internal/cloud/m365"
	"github.com/Metrix-Cyber/athar/internal/report"
)

// The connector's original interface asked the operator to obtain a bearer
// token themselves and pass it through an environment variable. That is a
// reasonable contract for a pipeline and the wrong one for the person this tool
// exists to serve: an administrator who has never opened a terminal and has no
// reason to learn a cloud CLI to find out whether their tenant enforces MFA.
//
// This serves a small local UI instead. The binary is double-clicked, a browser
// opens, the administrator signs in on Microsoft's or Google's own page, and
// the report appears. No commands, no tokens, no environment variables.
//
// It binds to the loopback interface only. The listener exists to receive the
// OAuth redirect and to render one report to the person sitting at the machine;
// exposing it on a routable address would publish a tenant assessment, and
// briefly an access token, to the network.

type server struct {
	mux  *http.ServeMux
	base string

	cfg  *uiConfig
	flow *auth.Flow
	prov string

	// done signals the process to exit once the operator closes the report.
	done chan struct{}
}

// uiConfig holds the application registration IDs between runs.
//
// Client IDs are not secrets — they are visible in the browser's address bar
// during sign-in — so storing them in plain JSON is appropriate. No token or
// refresh token is ever persisted: a credential that can read a directory
// should not outlive the assessment that needed it.
type uiConfig struct {
	M365ClientID   string `json:"m365_client_id,omitempty"`
	GoogleClientID string `json:"google_client_id,omitempty"`

	path string
}

func configPath() string {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "athar-cloud.json"
	}
	return filepath.Join(dir, "athar", "cloud.json")
}

func loadConfig() *uiConfig {
	c := &uiConfig{path: configPath()}
	if b, err := os.ReadFile(c.path); err == nil {
		_ = json.Unmarshal(b, c)
	}
	return c
}

func (c *uiConfig) save() {
	if err := os.MkdirAll(filepath.Dir(c.path), 0o700); err != nil {
		return
	}
	if b, err := json.MarshalIndent(c, "", "  "); err == nil {
		_ = os.WriteFile(c.path, b, 0o600)
	}
}

func (c *uiConfig) setClientID(prov, id string) {
	if prov == "m365" {
		c.M365ClientID = id
	} else {
		c.GoogleClientID = id
	}
	c.save()
}

// runUI serves the interface and blocks until the assessment is finished and
// the operator has been shown the result.
func runUI() error {
	// Port zero: the OS picks a free port. A fixed port would collide with
	// whatever else the machine is running and would let any local process
	// predict where the redirect lands.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return fmt.Errorf("starting local interface: %w", err)
	}

	s := &server{
		mux:  http.NewServeMux(),
		base: fmt.Sprintf("http://127.0.0.1:%d", ln.Addr().(*net.TCPAddr).Port),
		cfg:  loadConfig(),
		done: make(chan struct{}),
	}
	s.routes()

	srv := &http.Server{
		Handler:           s.mux,
		ReadHeaderTimeout: 10 * time.Second,
	}
	go func() { _ = srv.Serve(ln) }()

	fmt.Printf("\n  Athar Cloud — tenant assessment\n\n")
	fmt.Printf("  Opening %s in your browser.\n", s.base)
	fmt.Printf("  If it does not open, paste that address into any browser.\n\n")

	if err := openURL(s.base); err != nil {
		fmt.Printf("  Could not open a browser automatically.\n")
	}

	<-s.done
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_ = srv.Shutdown(ctx)
	return nil
}

func (s *server) routes() {
	s.mux.HandleFunc("/", s.handleHome)
	s.mux.HandleFunc("/start", s.handleStart)
	s.mux.HandleFunc("/callback", s.handleCallback)
	s.mux.HandleFunc("/quit", s.handleQuit)
}

func (s *server) handleHome(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	render(w, pageHome, map[string]any{
		"M365ClientID":   s.cfg.M365ClientID,
		"GoogleClientID": s.cfg.GoogleClientID,
		"M365Scopes":     auth.MicrosoftScopes,
		"GoogleScopes":   auth.GoogleScopes,
		"Redirect":       s.base + "/callback",
	})
}

// handleStart begins sign-in and sends the browser to the provider.
func (s *server) handleStart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	prov := r.FormValue("provider")
	if prov != "m365" && prov != "google" {
		s.fail(w, "Choose Microsoft 365 or Google Workspace.", "")
		return
	}

	// Each provider has its own field, so switching between them does not
	// discard the other's saved ID.
	clientID := strings.TrimSpace(r.FormValue("client_id_" + prov))
	if clientID == "" {
		name := "Application (client) ID"
		if prov == "google" {
			name = "OAuth client ID"
		}
		s.fail(w, "An "+name+" is required.",
			"Register an application in your own tenant and paste its ID into the box for the provider you selected. The setup steps are on the previous page.")
		return
	}

	cfg, err := auth.ForProvider(prov, clientID, s.base+"/callback")
	if err != nil {
		s.fail(w, "Unknown provider.", err.Error())
		return
	}

	flow, authURL, err := auth.Begin(cfg)
	if err != nil {
		s.fail(w, "Could not start sign-in.", err.Error())
		return
	}

	s.flow, s.prov = flow, prov
	s.cfg.setClientID(prov, clientID)
	http.Redirect(w, r, authURL, http.StatusSeeOther)
}

// handleCallback receives the provider's redirect, exchanges the code, runs the
// assessment and renders the report.
func (s *server) handleCallback(w http.ResponseWriter, r *http.Request) {
	if s.flow == nil {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	if e := r.URL.Query().Get("error"); e != "" {
		detail := r.URL.Query().Get("error_description")
		if e == "access_denied" {
			detail = "Sign-in was cancelled, or an administrator has restricted which applications may read the directory."
		}
		s.fail(w, "Sign-in did not complete.", detail)
		return
	}

	// The state parameter is the only thing distinguishing the provider's
	// redirect from a link a user was tricked into following, which would
	// otherwise let a third party's authorization code be exchanged here.
	if r.URL.Query().Get("state") != s.flow.State() {
		s.fail(w, "Sign-in could not be verified.",
			"The response did not match the request this program started. Close the browser and run the program again.")
		return
	}

	code := r.URL.Query().Get("code")
	if code == "" {
		s.fail(w, "Sign-in did not complete.", "The provider returned no authorization code.")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Minute)
	defer cancel()

	tok, err := s.flow.Exchange(ctx, code)
	if err != nil {
		s.fail(w, "Sign-in failed.", err.Error())
		return
	}

	rep, paths, err := s.assess(r.Context(), tok)
	if err != nil {
		s.fail(w, "The assessment could not be completed.", err.Error())
		return
	}

	var pass, failed, unknown int
	for _, f := range rep.Findings {
		switch string(f.Status) {
		case "pass":
			pass++
		case "fail":
			failed++
		case "unknown":
			unknown++
		}
	}

	render(w, pageDone, map[string]any{
		"Provider": rep.Provider,
		"Tenant":   rep.Tenant,
		"Pass":     pass,
		"Fail":     failed,
		"Unknown":  unknown,
		"Total":    len(rep.Findings),
		"HTML":     paths.html,
		"JSON":     paths.json,
		"Dir":      filepath.Dir(paths.html),
	})
}

type outputs struct{ html, json string }

// assess runs the checks and writes both machine-readable and human-readable
// output beside the executable.
func (s *server) assess(ctx context.Context, tok auth.Token) (cloud.Report, outputs, error) {
	var p cloud.Provider
	var baseURL string
	if s.prov == "m365" {
		p, baseURL = m365.Provider{}, m365.GraphBaseURL
	} else {
		p, baseURL = google.Provider{}, google.AdminBaseURL
	}

	client := &cloud.Client{
		BaseURL: baseURL,
		Token: func(context.Context) (string, error) {
			if tok.Expired() {
				return "", fmt.Errorf("the sign-in expired during the assessment; run the program again")
			}
			return tok.AccessToken, nil
		},
	}

	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()

	rep := cloud.Run(ctx, p, client, "")

	dir := outputDir()
	stamp := time.Now().Format("20060102-1504")
	out := outputs{
		json: filepath.Join(dir, fmt.Sprintf("athar-%s-%s.json", s.prov, stamp)),
		html: filepath.Join(dir, fmt.Sprintf("athar-%s-%s.html", s.prov, stamp)),
	}

	data, err := json.MarshalIndent(rep, "", "  ")
	if err != nil {
		return rep, out, err
	}
	// 0600: the report describes weaknesses in a production tenant.
	if err := os.WriteFile(out.json, data, 0o600); err != nil {
		return rep, out, err
	}

	f, err := os.OpenFile(out.html, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return rep, out, err
	}
	defer f.Close()

	src := report.Source{
		Kind:   "tenant",
		Name:   rep.Provider,
		Detail: rep.Tenant,
		When:   rep.StartedAt,
	}
	if err := report.Render(f, "ecc", []report.Source{src}, rep.Findings, "", "Metrix Cyber"); err != nil {
		return rep, out, err
	}
	return rep, out, nil
}

func (s *server) handleQuit(w http.ResponseWriter, r *http.Request) {
	render(w, pageClosed, nil)
	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}
	select {
	case <-s.done:
	default:
		close(s.done)
	}
}

func (s *server) fail(w http.ResponseWriter, headline, detail string) {
	w.WriteHeader(http.StatusOK)
	render(w, pageError, map[string]any{"Headline": headline, "Detail": detail})
}

func render(w http.ResponseWriter, tmpl *template.Template, data any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	// This page is served to a browser on the same machine and embeds no
	// third-party resources; a restrictive policy costs nothing and closes off
	// injection through any field rendered here.
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'")
	w.Header().Set("Referrer-Policy", "no-referrer")
	if err := tmpl.Execute(w, data); err != nil {
		fmt.Fprintf(os.Stderr, "rendering page: %v\n", err)
	}
}

// outputDir puts results beside the executable, falling back to the working
// directory when that location is not writable — which it often is not when the
// program is run from Downloads or a network share.
func outputDir() string {
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
