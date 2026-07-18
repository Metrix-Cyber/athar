//go:build windows

package windows

import (
	"context"
	"fmt"

	"github.com/Metrix-Cyber/athar/internal/check"
	"github.com/Metrix-Cyber/athar/internal/finding"
)

// ECC 2-15 covers web application security.
var webCodes = []string{"2-15-2"}

func init() {
	check.Register(check.Check{
		ID: "win.web.server", Subdomain: "2-15", ControlCodes: webCodes,
		Platforms: []string{"windows"}, Run: webServer,
	})
}

// webServers are services indicating a web server is hosted locally.
var webServers = map[string]string{
	"Internet Information Services": "W3SVC",
	"Apache":                        "Apache2.4",
	"nginx":                         "nginx",
	"Tomcat":                        "Tomcat9",
}

// webServer reports locally hosted web servers.
//
// Where no web server runs, the subdomain is not applicable to this host
// rather than passing — a host that cannot fail a control has not satisfied
// it, and recording that distinction keeps the aggregate score honest.
func webServer(ctx context.Context) []finding.Finding {
	f := finding.New("win.web.server", "Locally hosted web server", "2-15", webCodes)

	var running []string
	for label, svc := range webServers {
		on, present, err := serviceState(svc)
		if err != nil || !present {
			continue
		}
		f = f.With(label+"_running", on)
		if on {
			running = append(running, label)
		}
	}

	if len(running) == 0 {
		return []finding.Finding{f.Inapplicable(
			"No web server is running on this host, so web application controls are assessed at the application tier rather than here.")}
	}

	return []finding.Finding{f.With("web_servers_running", running).
		Failed(finding.Medium,
			fmt.Sprintf("This host runs %s. Web applications require security testing, secure configuration and protection appropriate to their exposure, none of which can be determined from the presence of the service alone.",
				joinList(running)),
			"Confirm the hosted applications are in scope of application security testing, that TLS and security headers are correctly configured, and that a web application firewall protects internet-facing services.")}
}
