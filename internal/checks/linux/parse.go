// Package linux holds Linux checks.
//
// Parsing logic lives in this file deliberately without a build constraint, so
// it compiles and is unit-tested on any development machine. Only the check
// registration and the live filesystem reads are Linux-only. Every parser
// takes its input as text rather than reading files itself, which is what
// makes fixture-based testing possible — and testing is not optional here,
// since these parsers cannot be exercised against a live host from a Windows
// workstation.
package linux

import (
	"bufio"
	"strconv"
	"strings"
)

// Account is one entry from /etc/passwd.
type Account struct {
	Name     string
	UID      int
	GID      int
	Home     string
	Shell    string
	System   bool // UID below the login threshold
	CanLogin bool // shell is not nologin/false
}

// nologinShells never permit an interactive session.
var nologinShells = map[string]bool{
	"/usr/sbin/nologin": true,
	"/sbin/nologin":     true,
	"/bin/false":        true,
	"/usr/bin/false":    true,
	"":                  true,
}

// ParsePasswd reads /etc/passwd content.
//
// uidMin is the threshold below which accounts are treated as system accounts;
// it comes from login.defs rather than being assumed, because distributions
// differ (500 on older Red Hat, 1000 on Debian and current Red Hat).
func ParsePasswd(content string, uidMin int) []Account {
	var out []Account
	sc := bufio.NewScanner(strings.NewReader(content))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		f := strings.Split(line, ":")
		if len(f) < 7 {
			continue
		}
		uid, err := strconv.Atoi(f[2])
		if err != nil {
			continue
		}
		gid, _ := strconv.Atoi(f[3])
		shell := f[6]
		out = append(out, Account{
			Name:     f[0],
			UID:      uid,
			GID:      gid,
			Home:     f[5],
			Shell:    shell,
			System:   uid < uidMin && uid != 0,
			CanLogin: !nologinShells[shell],
		})
	}
	return out
}

// LoginDefs holds the password ageing policy from /etc/login.defs.
type LoginDefs struct {
	PassMaxDays int
	PassMinDays int
	PassMinLen  int
	PassWarnAge int
	UIDMin      int
	// Found records which keys were present; absent keys fall back to
	// distribution defaults, which is a materially different finding from a
	// key explicitly set to a weak value.
	Found map[string]bool
}

// ParseLoginDefs reads /etc/login.defs content.
func ParseLoginDefs(content string) LoginDefs {
	d := LoginDefs{PassMaxDays: -1, PassMinDays: -1, PassMinLen: -1,
		PassWarnAge: -1, UIDMin: 1000, Found: map[string]bool{}}

	sc := bufio.NewScanner(strings.NewReader(content))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		v, err := strconv.Atoi(fields[1])
		if err != nil {
			continue
		}
		switch strings.ToUpper(fields[0]) {
		case "PASS_MAX_DAYS":
			d.PassMaxDays, d.Found["PASS_MAX_DAYS"] = v, true
		case "PASS_MIN_DAYS":
			d.PassMinDays, d.Found["PASS_MIN_DAYS"] = v, true
		case "PASS_MIN_LEN":
			d.PassMinLen, d.Found["PASS_MIN_LEN"] = v, true
		case "PASS_WARN_AGE":
			d.PassWarnAge, d.Found["PASS_WARN_AGE"] = v, true
		case "UID_MIN":
			d.UIDMin, d.Found["UID_MIN"] = v, true
		}
	}
	return d
}

// SSHDConfig holds the settings relevant to remote access hardening.
type SSHDConfig struct {
	PermitRootLogin        string
	PasswordAuthentication string
	PermitEmptyPasswords   string
	X11Forwarding          string
	MaxAuthTries           int
	ClientAliveInterval    int
	Port                   []string
	Ciphers                []string
	MACs                   []string
	KexAlgorithms          []string
	Found                  map[string]bool
}

// ParseSSHDConfig reads sshd_config content.
//
// Directives are case-insensitive and the FIRST occurrence wins in OpenSSH —
// the opposite of most configuration formats. Taking the last value would
// report a setting the daemon is not using.
func ParseSSHDConfig(content string) SSHDConfig {
	c := SSHDConfig{MaxAuthTries: -1, ClientAliveInterval: -1, Found: map[string]bool{}}

	set := func(key string, apply func()) {
		if c.Found[key] {
			return // first occurrence wins
		}
		c.Found[key] = true
		apply()
	}

	sc := bufio.NewScanner(strings.NewReader(content))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		key := strings.ToLower(fields[0])
		val := fields[1]

		switch key {
		case "permitrootlogin":
			set(key, func() { c.PermitRootLogin = val })
		case "passwordauthentication":
			set(key, func() { c.PasswordAuthentication = val })
		case "permitemptypasswords":
			set(key, func() { c.PermitEmptyPasswords = val })
		case "x11forwarding":
			set(key, func() { c.X11Forwarding = val })
		case "maxauthtries":
			set(key, func() { c.MaxAuthTries, _ = strconv.Atoi(val) })
		case "clientaliveinterval":
			set(key, func() { c.ClientAliveInterval, _ = strconv.Atoi(val) })
		case "port":
			c.Port = append(c.Port, val)
			c.Found[key] = true
		case "ciphers":
			set(key, func() { c.Ciphers = splitList(val) })
		case "macs":
			set(key, func() { c.MACs = splitList(val) })
		case "kexalgorithms":
			set(key, func() { c.KexAlgorithms = splitList(val) })
		}
	}
	return c
}

func splitList(s string) []string {
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// Listener is one socket from /proc/net/tcp or /proc/net/udp.
type Listener struct {
	Proto    string
	Address  string
	Port     int
	Loopback bool
}

// tcpStateListen is the TCP_LISTEN state value in /proc/net/tcp.
const tcpStateListen = "0A"

// ParseProcNet reads /proc/net/tcp or /proc/net/udp content.
//
// Addresses are little-endian hex, so 0100007F is 127.0.0.1 rather than
// 1.0.0.127. Getting the byte order wrong would classify every loopback-only
// service as network-exposed and produce a report full of false findings.
func ParseProcNet(content, proto string) []Listener {
	var out []Listener
	sc := bufio.NewScanner(strings.NewReader(content))
	first := true
	for sc.Scan() {
		if first { // header row
			first = false
			continue
		}
		fields := strings.Fields(sc.Text())
		if len(fields) < 4 {
			continue
		}
		if proto == "tcp" && fields[3] != tcpStateListen {
			continue
		}
		addr, port, ok := parseHexAddr(fields[1])
		if !ok {
			continue
		}
		out = append(out, Listener{
			Proto:    proto,
			Address:  addr,
			Port:     port,
			Loopback: strings.HasPrefix(addr, "127."),
		})
	}
	return out
}

// parseHexAddr converts "0100007F:0016" to ("127.0.0.1", 22).
func parseHexAddr(s string) (string, int, bool) {
	parts := strings.Split(s, ":")
	if len(parts) != 2 || len(parts[0]) != 8 {
		return "", 0, false
	}
	var octets [4]int
	for i := 0; i < 4; i++ {
		v, err := strconv.ParseInt(parts[0][i*2:i*2+2], 16, 32)
		if err != nil {
			return "", 0, false
		}
		octets[3-i] = int(v) // little-endian
	}
	port, err := strconv.ParseInt(parts[1], 16, 32)
	if err != nil {
		return "", 0, false
	}
	return strconv.Itoa(octets[0]) + "." + strconv.Itoa(octets[1]) + "." +
		strconv.Itoa(octets[2]) + "." + strconv.Itoa(octets[3]), int(port), true
}

// OSRelease holds identity fields from /etc/os-release.
type OSRelease struct {
	ID         string
	Name       string
	Version    string
	VersionID  string
	PrettyName string
}

// ParseOSRelease reads /etc/os-release content.
func ParseOSRelease(content string) OSRelease {
	var r OSRelease
	sc := bufio.NewScanner(strings.NewReader(content))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		v = strings.Trim(strings.TrimSpace(v), `"'`)
		switch strings.ToUpper(strings.TrimSpace(k)) {
		case "ID":
			r.ID = v
		case "NAME":
			r.Name = v
		case "VERSION":
			r.Version = v
		case "VERSION_ID":
			r.VersionID = v
		case "PRETTY_NAME":
			r.PrettyName = v
		}
	}
	return r
}

// WeakSSHAlgorithms returns the entries considered cryptographically weak.
//
// The lists are conservative: only algorithms with published practical
// weaknesses are named, so a finding here is defensible to an assessor rather
// than a matter of preference.
func WeakSSHAlgorithms(ciphers, macs, kex []string) (weakCiphers, weakMACs, weakKex []string) {
	badCipher := []string{"3des", "arcfour", "blowfish", "cast128", "des-cbc", "rc4"}
	badMAC := []string{"hmac-md5", "hmac-sha1-96", "hmac-md5-96", "umac-64"}
	badKex := []string{"diffie-hellman-group1-", "diffie-hellman-group-exchange-sha1",
		"diffie-hellman-group14-sha1", "rsa1024-"}

	match := func(vals, bad []string) []string {
		var hits []string
		for _, v := range vals {
			lv := strings.ToLower(v)
			for _, b := range bad {
				if strings.Contains(lv, b) {
					hits = append(hits, v)
					break
				}
			}
		}
		return hits
	}
	return match(ciphers, badCipher), match(macs, badMAC), match(kex, badKex)
}
