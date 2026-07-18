//go:build linux

package main

import (
	"os"
	"strings"

	"github.com/Metrix-Cyber/athar/internal/check"
)

// isElevated reports whether the scan runs as root. Checks needing privilege
// report undetermined rather than guessing when it is absent.
func isElevated() bool { return os.Geteuid() == 0 }

// osVersion returns the running kernel release.
func osVersion() string {
	b, err := os.ReadFile("/proc/sys/kernel/osrelease")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

// edition returns the distribution identifier, the closest Linux analogue to a
// Windows edition.
func edition() string {
	b, err := os.ReadFile("/etc/os-release")
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(b), "\n") {
		if k, v, ok := strings.Cut(strings.TrimSpace(line), "="); ok &&
			strings.EqualFold(strings.TrimSpace(k), "PRETTY_NAME") {
			return strings.Trim(strings.TrimSpace(v), `"'`)
		}
	}
	return ""
}

// management determines how the host's configuration is administered.
//
// Linux has no single directory equivalent to Active Directory, so this looks
// for the mechanisms that actually apply configuration centrally: a
// configuration management agent, or domain integration via SSSD/realmd.
// Reporting "standalone" drives the report toward scripted-baseline guidance,
// which is the correct advice for an unmanaged host.
func management(ed string) check.Management {
	m := check.Management{}

	// Domain integration.
	for _, p := range []string{"/etc/sssd/sssd.conf", "/etc/krb5.conf"} {
		if b, err := os.ReadFile(p); err == nil {
			for _, line := range strings.Split(string(b), "\n") {
				line = strings.TrimSpace(line)
				if strings.HasPrefix(line, "default_realm") ||
					strings.HasPrefix(line, "domains") {
					if _, v, ok := strings.Cut(line, "="); ok {
						m.Domain = strings.TrimSpace(v)
						m.DomainJoined = m.Domain != ""
					}
				}
			}
		}
	}

	// Configuration management agents are the Linux equivalent of centrally
	// applied policy.
	agents := map[string]string{
		"/opt/puppetlabs":     "Puppet",
		"/etc/salt/minion":    "Salt",
		"/etc/chef/client.rb": "Chef",
		"/etc/ansible":        "Ansible",
	}
	for path, name := range agents {
		if _, err := os.Stat(path); err == nil {
			m.MDMProviders = append(m.MDMProviders, name)
		}
	}

	switch {
	case len(m.MDMProviders) > 0:
		m.Mode = "mdm"
	case m.DomainJoined:
		m.Mode = "domain"
	default:
		m.Mode = "standalone"
	}
	return m
}
