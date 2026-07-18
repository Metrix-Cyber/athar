package linux

import "testing"

// Fixtures are real file content from Debian/Ubuntu and RHEL hosts. These
// tests are the only verification these parsers get before running on a
// customer machine, so they cover the cases that would silently produce wrong
// findings rather than merely exercising the happy path.

const passwdFixture = `root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sshd:x:104:65534::/run/sshd:/usr/sbin/nologin
ubuntu:x:1000:1000:Ubuntu:/home/ubuntu:/bin/bash
deploy:x:1001:1001::/home/deploy:/bin/sh
svc_backup:x:998:998::/var/lib/backup:/bin/false
# a comment line
malformed:x:notanumber:0::/:/bin/sh
`

func TestParsePasswd(t *testing.T) {
	got := ParsePasswd(passwdFixture, 1000)

	if len(got) != 7 {
		t.Fatalf("account count = %d, want 7 (comment and malformed rows must be skipped)", len(got))
	}

	by := map[string]Account{}
	for _, a := range got {
		by[a.Name] = a
	}

	// root is UID 0: a system UID, but never classified as a system account,
	// because privileged-account findings must always include it.
	if by["root"].System {
		t.Error("root must not be classified as a system account")
	}
	if !by["root"].CanLogin {
		t.Error("root has /bin/bash and must be able to log in")
	}
	if !by["sshd"].System {
		t.Error("sshd (UID 104) should be a system account when UID_MIN is 1000")
	}
	if by["sshd"].CanLogin {
		t.Error("sshd has /usr/sbin/nologin and must not be able to log in")
	}
	if by["ubuntu"].System {
		t.Error("ubuntu (UID 1000) is at UID_MIN and is not a system account")
	}
	if by["svc_backup"].CanLogin {
		t.Error("/bin/false must not count as a login shell")
	}
}

func TestParsePasswdUIDMinVaries(t *testing.T) {
	// Older Red Hat uses UID_MIN 500; the same file must classify differently.
	got := ParsePasswd("app:x:600:600::/home/app:/bin/bash\n", 1000)
	if !got[0].System {
		t.Error("UID 600 is a system account when UID_MIN is 1000")
	}
	got = ParsePasswd("app:x:600:600::/home/app:/bin/bash\n", 500)
	if got[0].System {
		t.Error("UID 600 is a login account when UID_MIN is 500")
	}
}

const loginDefsFixture = `# comment
PASS_MAX_DAYS	90
PASS_MIN_DAYS	7
PASS_WARN_AGE	14
UID_MIN			 1000
`

func TestParseLoginDefs(t *testing.T) {
	d := ParseLoginDefs(loginDefsFixture)

	if d.PassMaxDays != 90 || d.PassMinDays != 7 || d.PassWarnAge != 14 {
		t.Errorf("ageing = %d/%d/%d, want 90/7/14", d.PassMaxDays, d.PassMinDays, d.PassWarnAge)
	}
	if d.UIDMin != 1000 {
		t.Errorf("UID_MIN = %d, want 1000", d.UIDMin)
	}
	// PASS_MIN_LEN is absent here. It must stay at the sentinel so the check
	// can distinguish "not configured" from "configured to zero".
	if d.PassMinLen != -1 {
		t.Errorf("absent PASS_MIN_LEN = %d, want -1 sentinel", d.PassMinLen)
	}
	if d.Found["PASS_MIN_LEN"] {
		t.Error("PASS_MIN_LEN must not be reported as found")
	}
	if !d.Found["PASS_MAX_DAYS"] {
		t.Error("PASS_MAX_DAYS must be reported as found")
	}
}

func TestParseLoginDefsDefaultUIDMin(t *testing.T) {
	// A file with no UID_MIN must still yield a usable default.
	if d := ParseLoginDefs("PASS_MAX_DAYS 30\n"); d.UIDMin != 1000 {
		t.Errorf("default UID_MIN = %d, want 1000", d.UIDMin)
	}
}

const sshdFixture = `# managed by config tool
Port 22
Port 2222
PermitRootLogin yes
#PermitRootLogin no
PasswordAuthentication yes
MaxAuthTries 6
Ciphers aes128-ctr,3des-cbc,aes256-gcm@openssh.com
MACs hmac-sha2-256,hmac-md5
KexAlgorithms curve25519-sha256,diffie-hellman-group14-sha1
PermitRootLogin no
`

func TestParseSSHDConfigFirstOccurrenceWins(t *testing.T) {
	c := ParseSSHDConfig(sshdFixture)

	// OpenSSH takes the FIRST value for a directive, not the last. Reading the
	// last would report PermitRootLogin as "no" on a host that actually
	// permits root login — a false pass on a critical control.
	if c.PermitRootLogin != "yes" {
		t.Errorf("PermitRootLogin = %q, want \"yes\" (first occurrence wins)", c.PermitRootLogin)
	}
	if c.PasswordAuthentication != "yes" {
		t.Errorf("PasswordAuthentication = %q, want \"yes\"", c.PasswordAuthentication)
	}
	if c.MaxAuthTries != 6 {
		t.Errorf("MaxAuthTries = %d, want 6", c.MaxAuthTries)
	}
	if len(c.Port) != 2 || c.Port[0] != "22" || c.Port[1] != "2222" {
		t.Errorf("Port = %v, want both 22 and 2222", c.Port)
	}
	// Commented directives must be ignored entirely.
	if c.ClientAliveInterval != -1 {
		t.Errorf("absent ClientAliveInterval = %d, want -1 sentinel", c.ClientAliveInterval)
	}
}

func TestWeakSSHAlgorithms(t *testing.T) {
	c := ParseSSHDConfig(sshdFixture)
	wc, wm, wk := WeakSSHAlgorithms(c.Ciphers, c.MACs, c.KexAlgorithms)

	if len(wc) != 1 || wc[0] != "3des-cbc" {
		t.Errorf("weak ciphers = %v, want [3des-cbc]", wc)
	}
	if len(wm) != 1 || wm[0] != "hmac-md5" {
		t.Errorf("weak MACs = %v, want [hmac-md5]", wm)
	}
	if len(wk) != 1 || wk[0] != "diffie-hellman-group14-sha1" {
		t.Errorf("weak kex = %v, want [diffie-hellman-group14-sha1]", wk)
	}
}

func TestWeakSSHAlgorithmsAcceptsStrong(t *testing.T) {
	wc, wm, wk := WeakSSHAlgorithms(
		[]string{"aes256-gcm@openssh.com", "chacha20-poly1305@openssh.com"},
		[]string{"hmac-sha2-512-etm@openssh.com"},
		[]string{"curve25519-sha256"},
	)
	if len(wc)+len(wm)+len(wk) != 0 {
		t.Errorf("modern algorithms flagged as weak: %v %v %v", wc, wm, wk)
	}
	// hmac-sha2-512 must not match the "hmac-sha1-96" pattern by accident.
	if _, wm2, _ := WeakSSHAlgorithms(nil, []string{"hmac-sha1-96"}, nil); len(wm2) != 1 {
		t.Error("hmac-sha1-96 should be flagged")
	}
}

// Header plus: sshd on 0.0.0.0:22, postgres on 127.0.0.1:5432, an established
// connection that must be ignored, and a UDP-style row.
const procNetTCPFixture = `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12345 1 0000000000000000 100 0 0 10 0
   1: 0100007F:1538 00000000:0000 0A 00000000:00000000 00:00000000 00000000   107        0 23456 1 0000000000000000 100 0 0 10 0
   2: 0100007F:1538 0100007F:C1B4 01 00000000:00000000 00:00000000 00000000  1000        0 34567 1 0000000000000000 20 4 30 10 -1
`

func TestParseProcNetTCP(t *testing.T) {
	got := ParseProcNet(procNetTCPFixture, "tcp")

	if len(got) != 2 {
		t.Fatalf("listener count = %d, want 2 (established connections must be excluded)", len(got))
	}

	// 00000000:0016 -> 0.0.0.0:22
	if got[0].Address != "0.0.0.0" || got[0].Port != 22 {
		t.Errorf("first listener = %s:%d, want 0.0.0.0:22", got[0].Address, got[0].Port)
	}
	if got[0].Loopback {
		t.Error("0.0.0.0 must not be classified as loopback")
	}

	// 0100007F is little-endian for 127.0.0.1; reading it big-endian would
	// give 1.0.0.127 and wrongly mark a local-only service as exposed.
	if got[1].Address != "127.0.0.1" || got[1].Port != 5432 {
		t.Errorf("second listener = %s:%d, want 127.0.0.1:5432", got[1].Address, got[1].Port)
	}
	if !got[1].Loopback {
		t.Error("127.0.0.1 must be classified as loopback")
	}
}

func TestParseProcNetUDPIgnoresState(t *testing.T) {
	// UDP rows carry state 07, not 0A, and must not be filtered out.
	const udp = `  sl  local_address rem_address   st
   0: 00000000:0044 00000000:0000 07 00000000:00000000 00:00000000
`
	if got := ParseProcNet(udp, "udp"); len(got) != 1 || got[0].Port != 68 {
		t.Errorf("udp listeners = %+v, want one on port 68", got)
	}
	if got := ParseProcNet(udp, "tcp"); len(got) != 0 {
		t.Errorf("tcp parse of a non-LISTEN row returned %d rows, want 0", len(got))
	}
}

const osReleaseFixture = `PRETTY_NAME="Ubuntu 24.04.1 LTS"
NAME="Ubuntu"
VERSION_ID="24.04"
VERSION="24.04.1 LTS (Noble Numbat)"
ID=ubuntu
ID_LIKE=debian
`

func TestParseOSRelease(t *testing.T) {
	r := ParseOSRelease(osReleaseFixture)
	if r.ID != "ubuntu" {
		t.Errorf("ID = %q, want ubuntu", r.ID)
	}
	if r.VersionID != "24.04" {
		t.Errorf("VERSION_ID = %q, want 24.04 (quotes must be stripped)", r.VersionID)
	}
	if r.PrettyName != "Ubuntu 24.04.1 LTS" {
		t.Errorf("PRETTY_NAME = %q", r.PrettyName)
	}
}

func TestParsersTolerateEmptyInput(t *testing.T) {
	// A truncated or unreadable file must yield empty results, never a panic:
	// the runner would convert a panic into an undetermined finding, but a
	// clean empty result lets the check report the situation accurately.
	if got := ParsePasswd("", 1000); len(got) != 0 {
		t.Error("empty passwd should yield no accounts")
	}
	if got := ParseProcNet("", "tcp"); len(got) != 0 {
		t.Error("empty proc net should yield no listeners")
	}
	_ = ParseSSHDConfig("")
	_ = ParseLoginDefs("")
	_ = ParseOSRelease("")
}
