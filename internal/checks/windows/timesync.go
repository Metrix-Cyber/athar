//go:build windows

package windows

import (
	"context"
	"fmt"
	"strings"

	"github.com/Metrix-Cyber/athar/internal/check"
	"github.com/Metrix-Cyber/athar/internal/finding"
)

// ECC 2-3-3-4 requires "centralized clock synchronization with an accurate and
// trusted source, such as sources provided by the Saudi Standards, Metrology
// and Quality Organization (SASO)".
//
// This is one of the few ECC clauses stating a concrete technical requirement,
// and it matters more than it looks: without synchronised clocks, event logs
// across hosts cannot be correlated, which undermines the incident
// investigation that other controls depend on.
var timeCodes = []string{"2-3-2", "2-3-3-4"}

func init() {
	check.Register(check.Check{
		ID: "win.time.synchronization", Subdomain: "2-3", ControlCodes: timeCodes,
		Platforms: []string{"windows"}, Run: timeSync,
	})
}

const w32time = `SYSTEM\CurrentControlSet\Services\W32Time`

func timeSync(ctx context.Context) []finding.Finding {
	f := finding.New("win.time.synchronization", "Time synchronisation", "2-3", timeCodes)

	running, present, err := serviceState("W32Time")
	if err != nil {
		return []finding.Finding{f.Undetermined(err)}
	}
	f = f.With("w32time_service_present", present).With("w32time_service_running", running)

	// NtpServer holds the configured peers; Type distinguishes domain
	// hierarchy (NT5DS) from explicit NTP peers (NTP) from none (NoSync).
	server, _ := regString(w32time+`\Parameters`, "NtpServer")
	syncType, _ := regString(w32time+`\Parameters`, "Type")
	f = f.With("ntp_source", server).With("sync_type", syncType)

	if !present || !running {
		return []finding.Finding{f.Failed(finding.Medium,
			"The Windows Time service is not running, so this host's clock is not being synchronised. Event timestamps cannot be reliably correlated with other systems during an investigation.",
			"Start and configure the Windows Time service against an approved time source.")}
	}

	switch {
	case strings.EqualFold(syncType, "NoSync"):
		return []finding.Finding{f.Failed(finding.Medium,
			"Time synchronisation is explicitly disabled (Type = NoSync). The clock will drift and event timestamps will not correlate with other hosts.",
			"Configure the host to synchronise against a centralised, trusted time source.")}

	case strings.EqualFold(syncType, "NT5DS"):
		return []finding.Finding{f.Passed(
			"The host synchronises time through the domain hierarchy. Confirm the domain's authoritative time source is an approved and trusted one.")}

	case server == "":
		return []finding.Finding{f.Failed(finding.Medium,
			"No time source is configured for the Windows Time service.",
			"Configure an approved centralised time source.")}
	}

	// A default public peer is not by itself a centralised, entity-controlled
	// source. Report it rather than passing silently.
	if strings.Contains(strings.ToLower(server), "time.windows.com") {
		return []finding.Finding{f.Failed(finding.Low,
			fmt.Sprintf("The host synchronises against the vendor default public time source (%s) rather than a centralised source under the entity's control.", server),
			"Point time synchronisation at the entity's internal time servers, traceable to an approved reference such as SASO.")}
	}

	return []finding.Finding{f.Passed(fmt.Sprintf(
		"Time synchronisation is active against %s. Confirm this source is approved and traceable to a trusted reference.", server))}
}
