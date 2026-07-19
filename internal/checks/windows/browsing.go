//go:build windows

package windows

import (
	"context"
	"strings"

	"golang.org/x/sys/windows/registry"

	"github.com/Metrix-Cyber/athar/internal/check"
	"github.com/Metrix-Cyber/athar/internal/finding"
)

// ECC 2-5-3-3 requires "secure browsing and internet connectivity, including
// strict restrictions on suspicious websites, file storage/sharing websites,
// and remote access websites"; 2-5-3-7 covers DNS security; 2-5-3-8 covers
// protection of the browsing channel against advanced persistent threats.
var (
	browseCodes = []string{"2-5-2", "2-5-3-3", "2-5-3-8"}
	dnsCodes    = []string{"2-5-2", "2-5-3-7"}
	ipsCodes    = []string{"2-5-2", "2-5-3-6"}
)

func init() {
	for _, c := range []check.Check{
		{ID: "win.net.secure_browsing", Subdomain: "2-5", ControlCodes: browseCodes,
			Platforms: []string{"windows"}, Run: secureBrowsing},
		{ID: "win.net.dns", Subdomain: "2-5", ControlCodes: dnsCodes,
			Platforms: []string{"windows"}, Run: dnsConfiguration},
		{ID: "win.net.intrusion_prevention", Subdomain: "2-5", ControlCodes: ipsCodes,
			Platforms: []string{"windows"}, Run: intrusionPrevention},
	} {
		check.Register(c)
	}
}

// secureBrowsing reports reputation-based protections on the browsing channel.
func secureBrowsing(ctx context.Context) []finding.Finding {
	f := finding.New("win.net.secure_browsing", "Browsing protection", "2-5", browseCodes)

	// SmartScreen for Windows and for Edge are separate policies.
	shellSS, shellSet, _ := dwordOr(policySystem, "EnableSmartScreen", 0)
	edgeSS, edgeSet, _ := dwordOr(`SOFTWARE\Policies\Microsoft\Edge`, "SmartScreenEnabled", 0)

	// Network Protection blocks connections to known-malicious hosts at the
	// endpoint, which is the closest host-side equivalent of the web filtering
	// this control expects.
	netProt, netSet, _ := dwordOr(
		`SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Network Protection`,
		"EnableNetworkProtection", 0)

	// A configured proxy indicates traffic passes through a filtering point.
	proxy, _ := regString(
		`SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings`, "ProxyServer")

	f = f.With("smartscreen_policy_enabled", shellSet && shellSS == 1).
		With("edge_smartscreen_policy_enabled", edgeSet && edgeSS == 1).
		With("network_protection_enabled", netSet && netProt == 1).
		With("proxy_configured", proxy != "")

	var missing []string
	if !shellSet || shellSS != 1 {
		missing = append(missing, "Windows SmartScreen is not enforced by policy")
	}
	if !netSet || netProt != 1 {
		missing = append(missing, "Defender Network Protection is not enabled")
	}

	if len(missing) > 0 {
		return []finding.Finding{f.Failed(finding.Medium,
			"Reputation-based browsing protection is not fully enforced on this host: "+joinList(missing)+
				". Where web filtering is provided by a network gateway instead, that should be evidenced separately, since it cannot be observed from the endpoint.",
			"Enforce SmartScreen and Defender Network Protection by policy, and evidence the gateway-level web filtering that ECC 2-5-3-3 expects.")}
	}

	return []finding.Finding{f.Passed(
		"SmartScreen and Network Protection are enforced by policy. Gateway-level web filtering still requires separate evidence.")}
}

// dnsConfiguration reports the resolvers in use and whether encrypted DNS is
// configured.
func dnsConfiguration(ctx context.Context) []finding.Finding {
	f := finding.New("win.net.dns", "DNS resolver configuration", "2-5", dnsCodes)

	servers := configuredDNSServers()
	f = f.With("configured_dns_servers", servers)

	// DoH policy: 2 = allowed, 3 = required.
	doh, dohSet, _ := dwordOr(`SOFTWARE\Policies\Microsoft\Windows NT\DNSClient`, "DoHPolicy", 0)
	f = f.With("doh_policy", doh).With("doh_policy_configured", dohSet)

	if len(servers) == 0 {
		return []finding.Finding{f.Undetermined(
			errNotSet)}
	}

	// Public resolvers indicate DNS is not being handled by entity-controlled
	// infrastructure, which prevents internal filtering and logging of
	// resolution — both things ECC 2-5-3-7 exists to obtain.
	publicResolvers := map[string]string{
		"8.8.8.8": "Google", "8.8.4.4": "Google",
		"1.1.1.1": "Cloudflare", "1.0.0.1": "Cloudflare",
		"9.9.9.9": "Quad9", "208.67.222.222": "OpenDNS",
	}
	var public []string
	for _, s := range servers {
		if name, ok := publicResolvers[s]; ok {
			public = append(public, s+" ("+name+")")
		}
	}

	if len(public) > 0 {
		f = f.With("public_resolvers_in_use", public)
		return []finding.Finding{f.Failed(finding.Low,
			"The host resolves DNS through public resolvers ("+joinList(public)+
				") rather than entity-controlled servers. DNS queries cannot be filtered, logged or inspected internally, which limits both threat detection and the security of the name service.",
			"Point DNS at the entity's own resolvers, and apply filtering and logging there.")}
	}

	return []finding.Finding{f.Passed(
		"DNS resolution uses non-public resolvers. Confirm those servers apply the filtering, logging and integrity protections that ECC 2-5-3-7 requires.")}
}

// configuredDNSServers reads statically configured resolvers from the
// interface registry. DHCP-assigned servers appear under a different value.
func configuredDNSServers() []string {
	const ifaces = `SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces`

	k, err := registry.OpenKey(registry.LOCAL_MACHINE, ifaces, registry.ENUMERATE_SUB_KEYS)
	if err != nil {
		return nil
	}
	names, _ := k.ReadSubKeyNames(-1)
	k.Close()

	seen := map[string]bool{}
	var out []string
	for _, n := range names {
		for _, val := range []string{"NameServer", "DhcpNameServer"} {
			s, err := regString(ifaces+`\`+n, val)
			if err != nil || s == "" {
				continue
			}
			for _, srv := range strings.FieldsFunc(s, func(r rune) bool {
				return r == ',' || r == ' '
			}) {
				if srv != "" && !seen[srv] {
					seen[srv] = true
					out = append(out, srv)
				}
			}
		}
	}
	return out
}

// intrusionPrevention reports host-based intrusion prevention capability.
func intrusionPrevention(ctx context.Context) []finding.Finding {
	f := finding.New("win.net.intrusion_prevention",
		"Intrusion prevention capability", "2-5", ipsCodes)

	// Endpoint detection and response products provide the host-side portion
	// of what ECC 2-5-3-6 requires. Network IPS is a separate control that
	// cannot be observed from an endpoint at all.
	products := map[string]string{
		"Microsoft Defender for Endpoint": "Sense",
		"CrowdStrike Falcon":              "CSFalconService",
		"SentinelOne":                     "SentinelAgent",
		"Sophos Intercept X":              "SntpService",
		"Trend Micro Apex One":            "TmListen",
		"Palo Alto Cortex XDR":            "cyserver",
		"Wazuh Agent":                     "WazuhSvc",
		"Elastic Endpoint":                "ElasticEndpoint",
	}

	var found []string
	for label, svc := range products {
		if running, present, err := serviceState(svc); err == nil && present {
			found = append(found, label)
			f = f.With("agent_"+label+"_running", running)
		}
	}
	f = f.With("endpoint_protection_products", found)

	// Defender's own exploit protection is a partial substitute where no
	// dedicated product is deployed.
	asr, asrSet, _ := dwordOr(
		`SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR`,
		"ExploitGuard_ASR_Rules", 0)
	f = f.With("asr_rules_enabled", asrSet && asr == 1)

	if len(found) > 0 {
		return []finding.Finding{f.Passed(
			"Host-based detection and response is deployed (" + joinList(found) +
				"). Network-level intrusion prevention is a separate requirement that cannot be observed from an endpoint and must be evidenced independently.")}
	}

	return []finding.Finding{f.Failed(finding.Medium,
		"No endpoint detection and response product was identified on this host. ECC 2-5-3-6 requires intrusion prevention; the network-level portion cannot be assessed from an endpoint, but no host-side capability was found either.",
		"Deploy endpoint detection and response, and evidence network intrusion prevention separately.")}
}
