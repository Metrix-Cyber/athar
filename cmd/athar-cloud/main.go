// Command athar-cloud assesses a Microsoft 365 or Google Workspace tenant
// against ECC controls that a host scan cannot reach.
//
// This is a separate binary from the host scanner by design. The scanner is
// offline, credential-free and read-only; a connector is necessarily none of
// those. Keeping them apart means the property that makes the scanner
// deployable inside a regulated environment is not traded away for tenant
// coverage.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"time"

	"github.com/Metrix-Cyber/athar/internal/cloud"
	"github.com/Metrix-Cyber/athar/internal/cloud/google"
	"github.com/Metrix-Cyber/athar/internal/cloud/m365"
)

var version = "dev"

func main() {
	var (
		provider = flag.String("provider", "", "tenant to assess: m365 or google")
		outPath  = flag.String("out", "", "write JSON report to this file (default: stdout)")
		list     = flag.Bool("list", false, "list checks and the read scopes they require, then exit")
		showVer  = flag.Bool("version", false, "print version and exit")
		timeout  = flag.Duration("timeout", 5*time.Minute, "overall assessment timeout")
		ui       = flag.Bool("ui", false, "sign in and assess through a local browser interface")
	)
	flag.Usage = usage
	flag.Parse()

	if *showVer {
		fmt.Printf("athar-cloud %s\n", version)
		return
	}
	if *list {
		listChecks()
		return
	}

	// The interface, not the flags, is the default path. Someone who
	// double-clicks the program, or runs it with no arguments because they do
	// not know what arguments to give, is exactly the person this tool is for —
	// and printing a usage message at them helps nobody. The flag interface
	// remains for pipelines, which pass arguments and redirect output.
	if *ui || len(os.Args) == 1 || launchedByDoubleClick() {
		if err := runUI(); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}

	p, baseURL, err := resolveProvider(*provider)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		flag.Usage()
		os.Exit(2)
	}

	// Credentials come from the environment, never from flags. A flag value
	// lands in shell history and in the process list, where any local user can
	// read it — an unacceptable way to handle a token that can read a whole
	// directory.
	token, tenant, err := credentials(*provider)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()
	ctx, cancelTimeout := context.WithTimeout(ctx, *timeout)
	defer cancelTimeout()

	client := &cloud.Client{
		BaseURL: baseURL,
		Token:   func(context.Context) (string, error) { return token, nil },
	}

	fmt.Fprintf(os.Stderr, "Assessing %s tenant %s...\n", p.Name(), tenant)
	rep := cloud.Run(ctx, p, client, tenant)

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

	var pass, fail, unknown int
	for _, f := range rep.Findings {
		switch string(f.Status) {
		case "pass":
			pass++
		case "fail":
			fail++
		case "unknown":
			unknown++
		}
	}
	fmt.Fprintf(os.Stderr, "\nDone — %d findings: %d pass, %d fail, %d undetermined.\n",
		len(rep.Findings), pass, fail, unknown)
	if unknown > 0 {
		fmt.Fprintln(os.Stderr,
			"Undetermined findings usually mean a read scope was not granted; run -list to see which each check needs.")
	}
}

func resolveProvider(name string) (cloud.Provider, string, error) {
	switch strings.ToLower(name) {
	case "m365", "microsoft", "microsoft-365":
		return m365.Provider{}, m365.GraphBaseURL, nil
	case "google", "workspace", "google-workspace":
		return google.Provider{}, google.AdminBaseURL, nil
	case "":
		return nil, "", fmt.Errorf("-provider is required")
	}
	return nil, "", fmt.Errorf("unknown provider %q", name)
}

// credentials reads the access token and tenant identifier from the
// environment.
//
// The token is obtained by the operator through their own tooling (az, gcloud,
// or an OAuth flow) rather than by this binary. That is deliberate: acquiring
// tokens would mean handling client secrets and refresh tokens, and a tool
// that never holds a long-lived credential is one an administrator can reason
// about.
func credentials(provider string) (token, tenant string, err error) {
	switch strings.ToLower(provider) {
	case "m365", "microsoft", "microsoft-365":
		token = os.Getenv("ATHAR_M365_TOKEN")
		tenant = os.Getenv("ATHAR_M365_TENANT")
		if token == "" {
			return "", "", fmt.Errorf(
				"ATHAR_M365_TOKEN is not set.\n\nObtain a read-only Graph token, for example:\n" +
					"  az account get-access-token --resource https://graph.microsoft.com --query accessToken -o tsv")
		}
	default:
		token = os.Getenv("ATHAR_GOOGLE_TOKEN")
		tenant = os.Getenv("ATHAR_GOOGLE_DOMAIN")
		if token == "" {
			// This previously suggested `gcloud auth print-access-token`. That
			// returns a Cloud Platform token carrying no Admin SDK scopes, so
			// every check would have reported "undetermined" no matter how the
			// domain was configured — advice that looked plausible and could
			// not work.
			return "", "", fmt.Errorf(
				"ATHAR_GOOGLE_TOKEN is not set.\n\n" +
					"The token must carry Admin SDK scopes:\n" +
					"  https://www.googleapis.com/auth/admin.directory.user.readonly\n" +
					"  https://www.googleapis.com/auth/admin.directory.domain.readonly\n\n" +
					"A default gcloud token does not carry these. Run without arguments to\n" +
					"sign in through the browser instead, which requests them correctly.")
		}
	}
	if tenant == "" {
		tenant = "(unspecified)"
	}
	return token, tenant, nil
}

func listChecks() {
	for _, p := range []cloud.Provider{m365.Provider{}, google.Provider{}} {
		fmt.Printf("\n%s\n%s\n", p.Name(), strings.Repeat("-", len(p.Name())))
		for _, c := range p.Checks() {
			fmt.Printf("  %-38s ECC %-5s %v\n", c.ID, c.Subdomain, c.ControlCodes)
			fmt.Printf("  %-38s scopes: %s\n", "", strings.Join(c.RequiredScopes, ", "))
		}
	}
	fmt.Println("\nAll scopes are read-only. This tool issues GET requests only and never writes to a tenant.")
}

func usage() {
	fmt.Fprintf(os.Stderr, `athar-cloud — tenant assessment against NCA ECC-2:2024

Run it with no arguments, or double-click it, to sign in through your browser
and get a report. That is the intended way to use this program and needs no
tokens, no environment variables and no cloud CLI.

  athar-cloud

The flags below exist for pipelines, which supply their own token:

  athar-cloud -provider m365   -out tenant.json
  athar-cloud -provider google -out tenant.json
  athar-cloud -list

Credentials for that mode are read from the environment, never from flags, so
they do not appear in shell history or the process list:

  Microsoft 365     ATHAR_M365_TOKEN, ATHAR_M365_TENANT
  Google Workspace  ATHAR_GOOGLE_TOKEN, ATHAR_GOOGLE_DOMAIN

Flags:
`)
	flag.PrintDefaults()
}
