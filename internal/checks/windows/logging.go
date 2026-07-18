//go:build windows

package windows

import (
	"context"
	"fmt"

	"github.com/Metrix-Cyber/athar/internal/check"
	"github.com/Metrix-Cyber/athar/internal/finding"
)

// ECC 2-12 is unusually specific for this framework:
//
//	2-12-3-1  Activation of event logs for critical information assets
//	2-12-3-3  Identification of SIEM techniques for log collection
//	2-12-3-5  Retention period of event logs (shall be at least 12 months)
//
// 2-12-3-5 states a hard number, which makes it directly assessable — unlike
// most ECC controls, which state that requirements shall exist.
var (
	logCodes       = []string{"2-12-2", "2-12-3-1"}
	retentionCodes = []string{"2-12-3-3", "2-12-3-5"}
)

func init() {
	for _, c := range []check.Check{
		{ID: "win.log.audit_configuration", Subdomain: "2-12", ControlCodes: logCodes,
			Platforms: []string{"windows"}, Run: auditConfiguration},
		{ID: "win.log.retention", Subdomain: "2-12", ControlCodes: retentionCodes,
			Platforms: []string{"windows"}, Run: logRetention},
	} {
		check.Register(c)
	}
}

const eventLogBase = `SYSTEM\CurrentControlSet\Services\EventLog`

// auditConfiguration checks that security-relevant auditing is switched on.
func auditConfiguration(ctx context.Context) []finding.Finding {
	var out []finding.Finding

	// Command-line capture in process creation events. Without it, 4688 events
	// record that a process ran but not what it was told to do, which strips
	// most investigative value from the log.
	cl := finding.New("win.log.process_command_line",
		"Process creation command-line auditing", "2-12", logCodes)
	v, present, err := dwordOr(
		`SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit`,
		"ProcessCreationIncludeCmdLine_Enabled", 0)
	switch {
	case err != nil:
		out = append(out, cl.Undetermined(err))
	case !present || v != 1:
		out = append(out, cl.With("command_line_auditing", false).
			Failed(finding.Medium,
				"Process creation events do not include command lines, so security event logs record that a process started but not the arguments it ran with. This materially limits incident investigation.",
				"Enable 'Include command line in process creation events' by Group Policy, alongside process creation auditing."))
	default:
		out = append(out, cl.With("command_line_auditing", true).
			Passed("Process creation events include command lines."))
	}

	// PowerShell script block logging captures what scripts actually executed,
	// including obfuscated and in-memory content.
	ps := finding.New("win.log.powershell_logging", "PowerShell script block logging", "2-12", logCodes)
	sb, sbPresent, err := dwordOr(
		`SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging`,
		"EnableScriptBlockLogging", 0)
	switch {
	case err != nil:
		out = append(out, ps.Undetermined(err))
	case !sbPresent || sb != 1:
		out = append(out, ps.With("script_block_logging", false).
			Failed(finding.Medium,
				"PowerShell script block logging is not enabled. Script activity, including obfuscated and memory-resident content, is not recorded.",
				"Enable PowerShell script block logging by Group Policy."))
	default:
		out = append(out, ps.With("script_block_logging", true).
			Passed("PowerShell script block logging is enabled."))
	}

	return out
}

// logRetention assesses local log sizing and whether logs are forwarded
// centrally, which is what ECC's 12-month retention requirement demands in
// practice.
func logRetention(ctx context.Context) []finding.Finding {
	f := finding.New("win.log.retention", "Event log retention and collection", "2-12", retentionCodes)

	for _, log := range []string{"Security", "System", "Application"} {
		if size, present, err := dwordOr(eventLogBase+`\`+log, "MaxSize", 0); err == nil && present {
			f = f.With(log+"_max_size_mb", size/(1024*1024))
		} else {
			f = f.With(log+"_max_size_mb", "not configured (operating system default)")
		}
	}

	// Windows Event Forwarding: a configured SubscriptionManager means logs
	// leave this host, which is the only way local rollover can be survived.
	const wefPath = `SOFTWARE\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager`
	forwarding := keyExists(wefPath)
	f = f.With("event_forwarding_configured", forwarding)

	// Common agents that ship logs off-host. Presence is evidence of central
	// collection even where native forwarding is not configured.
	agents := map[string]string{
		"Splunk Universal Forwarder": "SplunkForwarder",
		"Elastic Agent":              "Elastic Agent",
		"Winlogbeat":                 "winlogbeat",
		"Wazuh Agent":                "WazuhSvc",
		"NXLog":                      "nxlog",
	}
	var found []string
	for label, svc := range agents {
		if running, present, err := serviceState(svc); err == nil && present {
			found = append(found, label)
			f = f.With("agent_"+svc+"_running", running)
		}
	}
	f = f.With("log_collection_agents", found)

	if forwarding || len(found) > 0 {
		how := "Windows Event Forwarding"
		if len(found) > 0 {
			how = joinList(found)
		}
		return []finding.Finding{f.Passed(fmt.Sprintf(
			"Event logs are collected centrally via %s. Confirm the collection platform retains cybersecurity event logs for at least 12 months as required by ECC 2-12-3-5.", how))}
	}

	return []finding.Finding{f.Failed(finding.High,
		"No central log collection was detected on this host. Local Windows event logs overwrite oldest entries when full, so they cannot evidence the minimum 12-month retention period that ECC 2-12-3-5 requires.",
		"Forward security event logs to a SIEM or central collector, and configure that platform to retain cybersecurity event logs for at least 12 months.")}
}
