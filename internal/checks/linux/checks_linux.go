//go:build linux

package linux

import (
	"context"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"sort"
	"strings"

	"github.com/Metrix-Cyber/athar/internal/check"
	"github.com/Metrix-Cyber/athar/internal/finding"
)

// Control codes mirror the Windows checks: the framework mapping belongs to
// the control, not the platform.
var (
	assetCodes  = []string{"2-1-2"}
	iamCodes    = []string{"2-2-2", "2-2-3-1"}
	privCodes   = []string{"2-2-3-3", "2-2-3-4"}
	netCodes    = []string{"2-5-2", "2-5-3-5"}
	epCodes     = []string{"2-3-2", "2-3-3-1"}
	cryptoCodes = []string{"2-8-2", "2-8-3-3"}
	vulnCodes   = []string{"2-10-2", "2-10-3-1", "2-10-3-4"}
	logCodes    = []string{"2-12-2", "2-12-3-1"}
	dataCodes   = []string{"2-7-2"}
)

func init() {
	for _, c := range []check.Check{
		{ID: "linux.asset.operating_system", Subdomain: "2-1", ControlCodes: assetCodes,
			Platforms: []string{"linux"}, Run: operatingSystem},
		{ID: "linux.iam.password_policy", Subdomain: "2-2", ControlCodes: iamCodes,
			Platforms: []string{"linux"}, Run: passwordPolicy},
		{ID: "linux.iam.accounts", Subdomain: "2-2", ControlCodes: privCodes,
			Platforms: []string{"linux"}, Run: accounts},
		{ID: "linux.net.ssh", Subdomain: "2-5", ControlCodes: netCodes,
			Platforms: []string{"linux"}, Run: sshConfiguration},
		{ID: "linux.net.listening_ports", Subdomain: "2-5", ControlCodes: netCodes,
			Platforms: []string{"linux"}, Run: listeningPorts},
		{ID: "linux.net.firewall", Subdomain: "2-5", ControlCodes: netCodes,
			Platforms: []string{"linux"}, Run: firewall},
		{ID: "linux.epp.mandatory_access_control", Subdomain: "2-3", ControlCodes: epCodes,
			Platforms: []string{"linux"}, Run: mandatoryAccessControl},
		{ID: "linux.crypto.ssh_algorithms", Subdomain: "2-8", ControlCodes: cryptoCodes,
			Platforms: []string{"linux"}, Run: sshAlgorithms},
		{ID: "linux.vuln.pending_updates", Subdomain: "2-10", ControlCodes: vulnCodes,
			Platforms: []string{"linux"}, Run: pendingUpdates},
		{ID: "linux.log.auditd", Subdomain: "2-12", ControlCodes: logCodes,
			Platforms: []string{"linux"}, Run: auditd},
		{ID: "linux.data.disk_encryption", Subdomain: "2-7", ControlCodes: dataCodes,
			Platforms: []string{"linux"}, Run: diskEncryption},
	} {
		check.Register(c)
	}
}

// readFile returns file content, distinguishing absence from a read error.
func readFile(path string) (string, bool, error) {
	b, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	return string(b), true, nil
}

func operatingSystem(ctx context.Context) []finding.Finding {
	f := finding.New("linux.asset.operating_system", "Operating system inventory", "2-1", assetCodes)

	content, present, err := readFile("/etc/os-release")
	if err != nil {
		return []finding.Finding{f.Undetermined(err)}
	}
	if !present {
		return []finding.Finding{f.Undetermined(fmt.Errorf("/etc/os-release not found"))}
	}

	r := ParseOSRelease(content)
	kernel, _, _ := readFile("/proc/sys/kernel/osrelease")
	f = f.With("distribution", r.ID).
		With("version", r.VersionID).
		With("pretty_name", r.PrettyName).
		With("kernel", strings.TrimSpace(kernel))

	return []finding.Finding{f.Passed(fmt.Sprintf(
		"Host runs %s (kernel %s). Vendor support status should be confirmed against the distribution's current lifecycle.",
		r.PrettyName, strings.TrimSpace(kernel)))}
}

func passwordPolicy(ctx context.Context) []finding.Finding {
	f := finding.New("linux.iam.password_policy", "Password ageing policy", "2-2", iamCodes)

	content, present, err := readFile("/etc/login.defs")
	if err != nil {
		return []finding.Finding{f.Undetermined(err)}
	}
	if !present {
		return []finding.Finding{f.Undetermined(fmt.Errorf("/etc/login.defs not found"))}
	}

	d := ParseLoginDefs(content)
	f = f.With("pass_max_days", d.PassMaxDays).
		With("pass_min_days", d.PassMinDays).
		With("pass_warn_age", d.PassWarnAge)

	// Complexity is enforced by PAM rather than login.defs; report whether a
	// quality module is configured rather than inferring strength.
	var quality []string
	for _, p := range []string{"/etc/security/pwquality.conf", "/etc/pam.d/common-password"} {
		if c, ok, _ := readFile(p); ok {
			if strings.Contains(c, "pam_pwquality") || strings.Contains(c, "pam_cracklib") ||
				strings.Contains(p, "pwquality.conf") {
				quality = append(quality, filepath.Base(p))
			}
		}
	}
	f = f.With("password_quality_modules", quality)

	var problems []string
	if !d.Found["PASS_MAX_DAYS"] || d.PassMaxDays <= 0 || d.PassMaxDays > 365 {
		problems = append(problems, "passwords are not required to expire")
	}
	if len(quality) == 0 {
		problems = append(problems, "no password quality module is configured")
	}

	if len(problems) > 0 {
		return []finding.Finding{f.Failed(finding.High,
			"Password policy is weaker than the expected baseline: "+strings.Join(problems, "; ")+".",
			"Set PASS_MAX_DAYS in /etc/login.defs and configure pam_pwquality with minimum length and complexity requirements.")}
	}
	return []finding.Finding{f.Passed(fmt.Sprintf(
		"Passwords expire after %d days and a password quality module is configured.", d.PassMaxDays))}
}

func accounts(ctx context.Context) []finding.Finding {
	f := finding.New("linux.iam.accounts", "Account and privilege hygiene", "2-2", privCodes)

	defs, _, _ := readFile("/etc/login.defs")
	uidMin := ParseLoginDefs(defs).UIDMin

	content, present, err := readFile("/etc/passwd")
	if err != nil || !present {
		return []finding.Finding{f.Undetermined(fmt.Errorf("reading /etc/passwd: %v", err))}
	}

	accts := ParsePasswd(content, uidMin)
	var login, uid0 []string
	for _, a := range accts {
		if a.UID == 0 {
			uid0 = append(uid0, a.Name)
		}
		if a.CanLogin && !a.System {
			login = append(login, a.Name)
		}
	}

	// Members of the administrative group hold privilege escalation rights.
	var admins []string
	for _, g := range []string{"sudo", "wheel", "admin"} {
		if grp, err := user.LookupGroup(g); err == nil {
			if members, err := groupMembers(grp.Gid, g); err == nil {
				admins = append(admins, members...)
			}
		}
	}
	sort.Strings(admins)

	f = f.With("uid_min", uidMin).
		With("login_accounts", login).
		With("uid_0_accounts", uid0).
		With("privileged_group_members", admins)

	if len(uid0) > 1 {
		return []finding.Finding{f.Failed(finding.Critical,
			fmt.Sprintf("%d accounts share UID 0 and therefore hold full root privilege: %s. Multiple UID 0 accounts defeat accountability and are a common persistence mechanism.",
				len(uid0), strings.Join(uid0, ", ")),
			"Ensure only the root account has UID 0; investigate any additional UID 0 account.")}
	}

	if len(admins) > 3 {
		return []finding.Finding{f.Failed(finding.Medium,
			fmt.Sprintf("%d accounts hold privilege escalation rights via sudo or wheel: %s. Privileged access should be limited to those requiring it.",
				len(admins), strings.Join(admins, ", ")),
			"Review privileged group membership against need and evidence periodic review of privileged access.")}
	}

	return []finding.Finding{f.Passed(fmt.Sprintf(
		"%d interactive account(s) and %d privileged account(s); a single UID 0 account.",
		len(login), len(admins)))}
}

// groupMembers reads secondary members of a group from /etc/group.
func groupMembers(gid, name string) ([]string, error) {
	content, ok, err := readFile("/etc/group")
	if err != nil || !ok {
		return nil, err
	}
	for _, line := range strings.Split(content, "\n") {
		fields := strings.Split(strings.TrimSpace(line), ":")
		if len(fields) >= 4 && fields[0] == name && fields[3] != "" {
			return strings.Split(fields[3], ","), nil
		}
	}
	return nil, nil
}

func sshConfiguration(ctx context.Context) []finding.Finding {
	f := finding.New("linux.net.ssh", "SSH daemon configuration", "2-5", netCodes)

	content, present, err := readFile("/etc/ssh/sshd_config")
	if err != nil {
		return []finding.Finding{f.Undetermined(err)}
	}
	if !present {
		return []finding.Finding{f.Inapplicable("No SSH daemon configuration is present on this host.")}
	}

	c := ParseSSHDConfig(content)
	f = f.With("permit_root_login", c.PermitRootLogin).
		With("password_authentication", c.PasswordAuthentication).
		With("max_auth_tries", c.MaxAuthTries).
		With("ports", c.Port)

	var problems []string
	if v := strings.ToLower(c.PermitRootLogin); v == "yes" {
		problems = append(problems, "root may log in directly over SSH")
	}
	if strings.EqualFold(c.PermitEmptyPasswords, "yes") {
		problems = append(problems, "empty passwords are permitted")
	}

	if len(problems) > 0 {
		return []finding.Finding{f.Failed(finding.High,
			"SSH is configured in a way that weakens remote access control: "+strings.Join(problems, "; ")+
				". Direct root login removes individual accountability for privileged actions.",
			"Set PermitRootLogin to 'no' (or 'prohibit-password'), disable empty passwords, and prefer key-based authentication.")}
	}

	if strings.EqualFold(c.PasswordAuthentication, "yes") {
		return []finding.Finding{f.Failed(finding.Medium,
			"SSH accepts password authentication, which is exposed to credential guessing and reuse. ECC 2-2-3-2 requires multi-factor authentication for remote access.",
			"Disable password authentication in favour of key-based or multi-factor authentication for remote access.")}
	}

	return []finding.Finding{f.Passed(
		"SSH does not permit direct root login and does not accept password authentication.")}
}

// riskyPorts mirrors the Windows list; the control concern is identical.
var riskyPorts = map[int]string{
	21: "FTP (credentials in clear text)", 23: "Telnet (credentials in clear text)",
	69: "TFTP (no authentication)", 111: "RPC portmapper", 512: "rexec", 513: "rlogin",
	514: "rshell", 1433: "Microsoft SQL Server", 1521: "Oracle database listener",
	3306: "MySQL", 5432: "PostgreSQL", 5900: "VNC", 6379: "Redis",
	11211: "memcached", 27017: "MongoDB",
}

func listeningPorts(ctx context.Context) []finding.Finding {
	f := finding.New("linux.net.listening_ports", "Listening network services", "2-5", netCodes)

	var all []Listener
	for _, src := range []struct{ path, proto string }{
		{"/proc/net/tcp", "tcp"}, {"/proc/net/udp", "udp"},
	} {
		content, ok, err := readFile(src.path)
		if err != nil {
			return []finding.Finding{f.Undetermined(err)}
		}
		if ok {
			all = append(all, ParseProcNet(content, src.proto)...)
		}
	}

	var external, risky []string
	seen := map[string]bool{}
	loopback := 0
	for _, l := range all {
		if l.Loopback {
			loopback++
			continue
		}
		external = append(external, fmt.Sprintf("%s/%d on %s", l.Proto, l.Port, l.Address))
		if desc, ok := riskyPorts[l.Port]; ok {
			key := fmt.Sprintf("%s/%d", l.Proto, l.Port)
			if !seen[key] {
				seen[key] = true
				risky = append(risky, fmt.Sprintf("%s (%s)", key, desc))
			}
		}
	}
	sort.Strings(external)
	sort.Strings(risky)

	f = f.With("externally_bound_listeners", external).
		With("loopback_only_listeners", loopback)

	if len(risky) > 0 {
		return []finding.Finding{f.With("services_requiring_justification", risky).
			Failed(finding.Medium,
				fmt.Sprintf("%d network service(s) listening on non-loopback addresses commonly require explicit justification: %s.",
					len(risky), strings.Join(risky, ", ")),
				"Confirm each listening service is required, and restrict the remainder by firewall rule to authorised source addresses.")}
	}
	return []finding.Finding{f.Passed(fmt.Sprintf(
		"%d service(s) listening on non-loopback addresses; none matched the list of services commonly requiring justification.",
		len(external)))}
}

func firewall(ctx context.Context) []finding.Finding {
	f := finding.New("linux.net.firewall", "Host firewall", "2-5", netCodes)

	// nf_tables and iptables both surface through /proc; presence of rules is
	// what matters, not which front end configured them.
	names, _, _ := readFile("/proc/net/ip_tables_names")
	nfConntrack := fileExists("/proc/net/nf_conntrack")
	ufwEnabled := false
	if c, ok, _ := readFile("/etc/ufw/ufw.conf"); ok {
		ufwEnabled = strings.Contains(strings.ToUpper(c), "ENABLED=YES")
	}

	f = f.With("ip_tables_names", strings.Fields(names)).
		With("ufw_enabled", ufwEnabled).
		With("conntrack_present", nfConntrack)

	if ufwEnabled || strings.Contains(names, "filter") {
		return []finding.Finding{f.Passed(
			"A host firewall is configured. Rule content should be reviewed against the entity's approved service baseline.")}
	}

	return []finding.Finding{f.Failed(finding.High,
		"No host firewall configuration was detected. Services on this host are reachable without host-level filtering.",
		"Enable and configure a host firewall (ufw, firewalld or nftables) permitting only required services.")}
}

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

func mandatoryAccessControl(ctx context.Context) []finding.Finding {
	f := finding.New("linux.epp.mandatory_access_control",
		"Mandatory access control", "2-3", epCodes)

	// SELinux
	if c, ok, _ := readFile("/sys/fs/selinux/enforce"); ok {
		enforcing := strings.TrimSpace(c) == "1"
		f = f.With("selinux_present", true).With("selinux_enforcing", enforcing)
		if enforcing {
			return []finding.Finding{f.Passed("SELinux is present and in enforcing mode.")}
		}
		return []finding.Finding{f.Failed(finding.Medium,
			"SELinux is present but not in enforcing mode, so its policy is logged rather than applied.",
			"Set SELinux to enforcing mode once policy violations have been resolved.")}
	}

	// AppArmor
	if fileExists("/sys/kernel/security/apparmor") {
		profiles, _, _ := readFile("/sys/kernel/security/apparmor/profiles")
		enforced := strings.Count(profiles, "(enforce)")
		f = f.With("apparmor_present", true).With("apparmor_enforced_profiles", enforced)
		if enforced > 0 {
			return []finding.Finding{f.Passed(fmt.Sprintf(
				"AppArmor is active with %d profile(s) in enforce mode.", enforced))}
		}
		return []finding.Finding{f.Failed(finding.Medium,
			"AppArmor is available but no profiles are in enforce mode.",
			"Enable and enforce AppArmor profiles for network-facing services.")}
	}

	return []finding.Finding{f.With("selinux_present", false).With("apparmor_present", false).
		Failed(finding.Medium,
			"Neither SELinux nor AppArmor is active. No mandatory access control constrains a compromised service beyond standard file permissions.",
			"Enable SELinux or AppArmor and enforce profiles for network-facing services.")}
}

func sshAlgorithms(ctx context.Context) []finding.Finding {
	f := finding.New("linux.crypto.ssh_algorithms", "SSH cryptographic algorithms", "2-8", cryptoCodes)

	content, present, err := readFile("/etc/ssh/sshd_config")
	if err != nil {
		return []finding.Finding{f.Undetermined(err)}
	}
	if !present {
		return []finding.Finding{f.Inapplicable("No SSH daemon configuration is present on this host.")}
	}

	c := ParseSSHDConfig(content)
	if len(c.Ciphers)+len(c.MACs)+len(c.KexAlgorithms) == 0 {
		return []finding.Finding{f.Passed(
			"No explicit SSH algorithm configuration is present, so OpenSSH defaults apply. " +
				"Defaults on current versions exclude known-weak algorithms, but the effective set should be " +
				"confirmed against the entity's required cryptographic standard level.")}
	}

	wc, wm, wk := WeakSSHAlgorithms(c.Ciphers, c.MACs, c.KexAlgorithms)
	f = f.With("ciphers", c.Ciphers).With("macs", c.MACs).With("kex_algorithms", c.KexAlgorithms).
		With("weak_ciphers", wc).With("weak_macs", wm).With("weak_kex", wk)

	if len(wc)+len(wm)+len(wk) > 0 {
		var parts []string
		if len(wc) > 0 {
			parts = append(parts, "ciphers "+strings.Join(wc, ", "))
		}
		if len(wm) > 0 {
			parts = append(parts, "MACs "+strings.Join(wm, ", "))
		}
		if len(wk) > 0 {
			parts = append(parts, "key exchange "+strings.Join(wk, ", "))
		}
		return []finding.Finding{f.Failed(finding.High,
			"SSH is configured to accept algorithms with known cryptographic weaknesses: "+strings.Join(parts, "; ")+".",
			"Restrict Ciphers, MACs and KexAlgorithms to current strong algorithms aligned with the National Cryptographic Standards.")}
	}

	return []finding.Finding{f.Passed(
		"Configured SSH algorithms contain no entries with known cryptographic weaknesses.")}
}

func pendingUpdates(ctx context.Context) []finding.Finding {
	f := finding.New("linux.vuln.pending_updates", "Pending security updates", "2-10", vulnCodes)

	// Debian/Ubuntu publish a machine-readable summary that is readable
	// without invoking a package manager.
	if c, ok, _ := readFile("/var/lib/update-notifier/updates-available"); ok {
		f = f.With("updates_available_notice", strings.TrimSpace(c))
	}

	// Reboot required after a kernel or libc update.
	rebootRequired := fileExists("/var/run/reboot-required") || fileExists("/run/reboot-required")
	f = f.With("reboot_required", rebootRequired)

	// Unattended upgrades configuration.
	autoUpdate := false
	if c, ok, _ := readFile("/etc/apt/apt.conf.d/20auto-upgrades"); ok {
		autoUpdate = strings.Contains(c, `"1"`)
		f = f.With("unattended_upgrades_configured", autoUpdate)
	}

	if rebootRequired {
		return []finding.Finding{f.Failed(finding.Medium,
			"The host requires a restart to complete installed updates. Patches that are installed but not applied do not protect the system until it reboots.",
			"Schedule a restart to activate pending kernel or library updates.")}
	}
	if !autoUpdate {
		return []finding.Finding{f.Failed(finding.Medium,
			"Automatic security updates do not appear to be configured. Patch application depends entirely on manual action.",
			"Configure unattended-upgrades or an equivalent managed patch process, and evidence its coverage of this host.")}
	}
	return []finding.Finding{f.Passed(
		"Automatic security updates are configured and no restart is pending.")}
}

func auditd(ctx context.Context) []finding.Finding {
	f := finding.New("linux.log.auditd", "Audit logging and collection", "2-12", logCodes)

	rulesPresent := false
	if entries, err := os.ReadDir("/etc/audit/rules.d"); err == nil && len(entries) > 0 {
		rulesPresent = true
		f = f.With("audit_rule_files", len(entries))
	}
	auditdInstalled := fileExists("/etc/audit/auditd.conf")
	f = f.With("auditd_installed", auditdInstalled).With("audit_rules_present", rulesPresent)

	// Remote log forwarding: the only way local rollover can be survived, and
	// what ECC 2-12-3-5's 12-month retention actually depends on.
	forwarding := false
	for _, p := range []string{"/etc/rsyslog.conf", "/etc/rsyslog.d", "/etc/audit/plugins.d/au-remote.conf"} {
		if c, ok, _ := readFile(p); ok && (strings.Contains(c, "@@") || strings.Contains(c, "active = yes")) {
			forwarding = true
		}
	}
	// Common shipping agents.
	for _, p := range []string{"/var/ossec/bin/wazuh-agentd", "/opt/splunkforwarder",
		"/usr/share/filebeat", "/usr/bin/nxlog"} {
		if fileExists(p) {
			forwarding = true
			f = f.With("log_shipper_detected", p)
		}
	}
	f = f.With("remote_forwarding_configured", forwarding)

	switch {
	case !auditdInstalled:
		return []finding.Finding{f.Failed(finding.High,
			"The audit daemon is not installed, so security-relevant system events are not recorded.",
			"Install and enable auditd with rules covering authentication, privilege use and audit configuration changes.")}
	case !rulesPresent:
		return []finding.Finding{f.Failed(finding.High,
			"The audit daemon is installed but no audit rules are configured, so it records little of security value.",
			"Deploy audit rules covering authentication, privileged command execution and changes to audit configuration.")}
	case !forwarding:
		return []finding.Finding{f.Failed(finding.High,
			"Audit logging is configured but no central log collection was detected. Local logs rotate and cannot evidence the minimum 12-month retention period that ECC 2-12-3-5 requires.",
			"Forward audit and system logs to a SIEM or central collector retaining cybersecurity event logs for at least 12 months.")}
	}
	return []finding.Finding{f.Passed(
		"Audit logging is configured with rules and logs are forwarded for central collection. " +
			"Confirm the collection platform retains cybersecurity event logs for at least 12 months.")}
}

func diskEncryption(ctx context.Context) []finding.Finding {
	f := finding.New("linux.data.disk_encryption", "Disk encryption", "2-7", dataCodes)

	// Device-mapper crypt targets appear under /sys/block as dm-* devices with
	// a "crypt" target in their dm/uuid.
	var encrypted []string
	entries, err := os.ReadDir("/sys/block")
	if err != nil {
		return []finding.Finding{f.Undetermined(err)}
	}
	for _, e := range entries {
		if !strings.HasPrefix(e.Name(), "dm-") {
			continue
		}
		uuid, ok, _ := readFile("/sys/block/" + e.Name() + "/dm/uuid")
		if ok && strings.HasPrefix(strings.TrimSpace(uuid), "CRYPT-") {
			name, _, _ := readFile("/sys/block/" + e.Name() + "/dm/name")
			encrypted = append(encrypted, strings.TrimSpace(name))
		}
	}

	crypttab, hasCrypttab, _ := readFile("/etc/crypttab")
	f = f.With("encrypted_volumes", encrypted).
		With("crypttab_present", hasCrypttab && strings.TrimSpace(crypttab) != "")

	if len(encrypted) == 0 {
		return []finding.Finding{f.Failed(finding.High,
			"No encrypted block devices were detected. Data at rest is readable if the disk is removed, or if the host is disposed of without secure erasure.",
			"Enable full disk encryption (LUKS) on volumes holding entity data, and manage recovery keys centrally.")}
	}

	return []finding.Finding{f.Passed(fmt.Sprintf(
		"%d encrypted volume(s) detected: %s. Confirm all volumes holding entity data are covered.",
		len(encrypted), strings.Join(encrypted, ", ")))}
}

// --- Additional technically-assessable clauses ---

var (
	timeCodes = []string{"2-3-2", "2-3-3-4"}
	dnsCodes  = []string{"2-5-2", "2-5-3-7"}
	ipsCodes  = []string{"2-5-2", "2-5-3-6"}
)

func init() {
	for _, c := range []check.Check{
		{ID: "linux.time.synchronization", Subdomain: "2-3", ControlCodes: timeCodes,
			Platforms: []string{"linux"}, Run: timeSync},
		{ID: "linux.net.dns", Subdomain: "2-5", ControlCodes: dnsCodes,
			Platforms: []string{"linux"}, Run: dnsConfiguration},
		{ID: "linux.net.intrusion_prevention", Subdomain: "2-5", ControlCodes: ipsCodes,
			Platforms: []string{"linux"}, Run: intrusionPrevention},
	} {
		check.Register(c)
	}
}

// timeSync reports clock synchronisation. ECC 2-3-3-4 requires a centralised,
// trusted source: without synchronised clocks, event logs across hosts cannot
// be correlated, which undermines the investigation other controls depend on.
func timeSync(ctx context.Context) []finding.Finding {
	f := finding.New("linux.time.synchronization", "Time synchronisation", "2-3", timeCodes)

	var (
		sources []string
		daemon  string
	)
	for _, src := range []struct{ path, name string }{
		{"/etc/chrony/chrony.conf", "chrony"},
		{"/etc/chrony.conf", "chrony"},
		{"/etc/ntp.conf", "ntpd"},
	} {
		if c, ok, _ := readFile(src.path); ok {
			if t := ParseChrony(c); t.Configured {
				sources, daemon = append(sources, t.Sources...), src.name
			}
		}
	}
	if len(sources) == 0 {
		for _, p := range []string{"/etc/systemd/timesyncd.conf"} {
			if c, ok, _ := readFile(p); ok {
				if t := ParseTimesyncd(c); t.Configured {
					sources, daemon = append(sources, t.Sources...), "systemd-timesyncd"
				}
			}
		}
	}

	f = f.With("daemon", daemon).With("time_sources", sources)

	if len(sources) == 0 {
		return []finding.Finding{f.Failed(finding.Medium,
			"No time synchronisation source is configured. The clock will drift and event timestamps will not correlate with other hosts during an investigation.",
			"Configure chrony, ntpd or systemd-timesyncd against the entity's centralised time source.")}
	}

	// A public pool is not a centralised source under the entity's control.
	var public []string
	for _, s := range sources {
		if strings.Contains(s, "pool.ntp.org") || strings.Contains(s, "ubuntu.com") ||
			strings.Contains(s, "debian.org") {
			public = append(public, s)
		}
	}
	if len(public) == len(sources) {
		return []finding.Finding{f.With("public_sources", public).Failed(finding.Low,
			fmt.Sprintf("Time synchronisation uses only public pools (%s) rather than a centralised source under the entity's control.",
				strings.Join(public, ", ")),
			"Point time synchronisation at the entity's internal time servers, traceable to an approved reference such as SASO.")}
	}

	return []finding.Finding{f.Passed(fmt.Sprintf(
		"Time synchronisation is configured via %s against %s. Confirm the source is approved and traceable to a trusted reference.",
		daemon, strings.Join(sources, ", ")))}
}

// dnsConfiguration reports the resolvers in use.
func dnsConfiguration(ctx context.Context) []finding.Finding {
	f := finding.New("linux.net.dns", "DNS resolver configuration", "2-5", dnsCodes)

	content, ok, err := readFile("/etc/resolv.conf")
	if err != nil {
		return []finding.Finding{f.Undetermined(err)}
	}
	if !ok {
		return []finding.Finding{f.Undetermined(fmt.Errorf("/etc/resolv.conf not present"))}
	}

	servers := ParseResolvConf(content)
	f = f.With("nameservers", servers)

	var public, loopback []string
	for _, s := range servers {
		if IsLoopbackResolver(s) {
			loopback = append(loopback, s)
			continue
		}
		if op, isPublic := PublicResolvers[s]; isPublic {
			public = append(public, s+" ("+op+")")
		}
	}
	f = f.With("public_resolvers_in_use", public).With("stub_resolvers", loopback)

	switch {
	case len(servers) == 0:
		return []finding.Finding{f.Failed(finding.Medium,
			"No nameserver is configured in /etc/resolv.conf.",
			"Configure the entity's DNS resolvers.")}

	case len(public) > 0:
		return []finding.Finding{f.Failed(finding.Low,
			"The host resolves DNS through public resolvers ("+strings.Join(public, ", ")+
				") rather than entity-controlled servers. Queries cannot be filtered, logged or inspected internally.",
			"Point DNS at the entity's own resolvers and apply filtering and logging there.")}

	case len(loopback) == len(servers):
		return []finding.Finding{f.Passed(
			"DNS resolution goes through a local stub resolver. The upstream servers it forwards to are not visible in /etc/resolv.conf and should be confirmed separately.")}
	}

	return []finding.Finding{f.Passed(
		"DNS resolution uses non-public resolvers. Confirm those servers apply the filtering, logging and integrity protections ECC 2-5-3-7 requires.")}
}

// intrusionPrevention reports host-based detection and response capability.
func intrusionPrevention(ctx context.Context) []finding.Finding {
	f := finding.New("linux.net.intrusion_prevention",
		"Intrusion prevention capability", "2-5", ipsCodes)

	products := map[string]string{
		"Wazuh Agent":        "/var/ossec/bin/wazuh-agentd",
		"CrowdStrike Falcon": "/opt/CrowdStrike/falconctl",
		"SentinelOne":        "/opt/sentinelone/bin/sentinelctl",
		"Elastic Endpoint":   "/opt/Elastic/Endpoint/elastic-endpoint",
		"osquery":            "/usr/bin/osqueryd",
		"Falco":              "/usr/bin/falco",
		"Fail2ban":           "/usr/bin/fail2ban-server",
		"Suricata":           "/usr/bin/suricata",
		"Snort":              "/usr/sbin/snort",
	}

	var found []string
	for label, path := range products {
		if fileExists(path) {
			found = append(found, label)
		}
	}
	sort.Strings(found)
	f = f.With("detection_products", found)

	if len(found) > 0 {
		return []finding.Finding{f.Passed(
			"Host-based detection is deployed (" + strings.Join(found, ", ") +
				"). Network-level intrusion prevention is a separate requirement that cannot be observed from a host and must be evidenced independently.")}
	}

	return []finding.Finding{f.Failed(finding.Medium,
		"No host-based intrusion detection or prevention capability was identified. ECC 2-5-3-6 requires intrusion prevention; the network-level portion cannot be assessed from a host, but no host-side capability was found either.",
		"Deploy host-based detection (such as Wazuh, Falco or an EDR agent) and evidence network intrusion prevention separately.")}
}
