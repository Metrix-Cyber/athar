package linux

import (
	"bufio"
	"strings"
)

// No build constraint: these parsers are unit-tested on any development
// machine, which is the only verification available for Linux checks written
// on a Windows workstation.

// TimeSync describes the host's clock synchronisation configuration.
type TimeSync struct {
	Sources    []string
	Configured bool
}

// ParseChrony reads chrony.conf or ntp.conf content, returning configured
// time sources.
//
// Both formats use "server <host>" or "pool <host>" directives. Options after
// the host are ignored, and commented directives must not count as configured
// sources.
func ParseChrony(content string) TimeSync {
	var t TimeSync
	sc := bufio.NewScanner(strings.NewReader(content))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "!") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		switch strings.ToLower(fields[0]) {
		case "server", "pool", "peer":
			t.Sources = append(t.Sources, fields[1])
			t.Configured = true
		}
	}
	return t
}

// ParseTimesyncd reads systemd-timesyncd configuration.
//
// It is an INI file where NTP= may list several space-separated servers on one
// line, unlike chrony's one-per-line form.
func ParseTimesyncd(content string) TimeSync {
	var t TimeSync
	sc := bufio.NewScanner(strings.NewReader(content))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key := strings.ToUpper(strings.TrimSpace(k))
		if key != "NTP" && key != "FALLBACKNTP" {
			continue
		}
		for _, s := range strings.Fields(v) {
			t.Sources = append(t.Sources, s)
			t.Configured = true
		}
	}
	return t
}

// ParseResolvConf returns the nameservers from /etc/resolv.conf.
func ParseResolvConf(content string) []string {
	var out []string
	sc := bufio.NewScanner(strings.NewReader(content))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) >= 2 && strings.EqualFold(fields[0], "nameserver") {
			out = append(out, fields[1])
		}
	}
	return out
}

// PublicResolvers maps well-known public DNS addresses to their operator.
// Resolution through these means queries cannot be filtered, logged or
// inspected by the entity — which is what ECC 2-5-3-7 exists to obtain.
var PublicResolvers = map[string]string{
	"8.8.8.8": "Google", "8.8.4.4": "Google",
	"1.1.1.1": "Cloudflare", "1.0.0.1": "Cloudflare",
	"9.9.9.9": "Quad9", "149.112.112.112": "Quad9",
	"208.67.222.222": "OpenDNS", "208.67.220.220": "OpenDNS",
}

// LoopbackResolvers are local stub resolvers. They forward upstream, so the
// real resolver is whatever they are configured to use — reporting them as
// "private" would be misleading.
func IsLoopbackResolver(addr string) bool {
	return strings.HasPrefix(addr, "127.") || addr == "::1"
}
