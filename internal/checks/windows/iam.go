//go:build windows

// Package windows holds Windows-only checks. Each file covers one ECC subdomain.
package windows

import (
	"context"
	"fmt"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/Metrix-Cyber/athar/internal/check"
	"github.com/Metrix-Cyber/athar/internal/finding"
)

func init() {
	check.Register(check.Check{
		ID:           "win.iam.password_policy",
		Subdomain:    "2-2",
		ControlCodes: []string{"2-2-2", "2-2-3-1"},
		Platforms:    []string{"windows"},
		Run:          passwordPolicy,
	})
	check.Register(check.Check{
		ID:           "win.iam.lockout_policy",
		Subdomain:    "2-2",
		ControlCodes: []string{"2-2-2", "2-2-3-1"},
		Platforms:    []string{"windows"},
		Run:          lockoutPolicy,
	})
	check.Register(check.Check{
		ID:           "win.iam.local_accounts",
		Subdomain:    "2-2",
		ControlCodes: []string{"2-2-3-1", "2-2-3-3", "2-2-3-4", "2-2-3-5"},
		Platforms:    []string{"windows"},
		Run:          localAccounts,
	})
}

var (
	netapi32          = windows.NewLazySystemDLL("netapi32.dll")
	procNetUserModals = netapi32.NewProc("NetUserModalsGet")
	procNetUserEnum   = netapi32.NewProc("NetUserEnum")
	procNetAPIFree    = netapi32.NewProc("NetApiBufferFree")
)

// userModalsInfo0 mirrors USER_MODALS_INFO_0 (password policy).
type userModalsInfo0 struct {
	MinPasswdLen    uint32
	MaxPasswdAge    uint32
	MinPasswdAge    uint32
	ForceLogoff     uint32
	PasswordHistLen uint32
}

// userModalsInfo3 mirrors USER_MODALS_INFO_3 (lockout policy).
type userModalsInfo3 struct {
	LockoutDuration          uint32
	LockoutObservationWindow uint32
	LockoutThreshold         uint32
}

// userInfo2 mirrors USER_INFO_2. Field order and types must match exactly;
// Go's natural alignment on amd64 reproduces the C layout.
type userInfo2 struct {
	Name         *uint16
	Password     *uint16
	PasswordAge  uint32
	Priv         uint32
	HomeDir      *uint16
	Comment      *uint16
	Flags        uint32
	ScriptPath   *uint16
	AuthFlags    uint32
	FullName     *uint16
	UsrComment   *uint16
	Parms        *uint16
	Workstations *uint16
	LastLogon    uint32
	LastLogoff   uint32
	AcctExpires  uint32
	MaxStorage   uint32
	UnitsPerWeek uint32
	LogonHours   *byte
	BadPwCount   uint32
	NumLogons    uint32
	LogonServer  *uint16
	CountryCode  uint32
	CodePage     uint32
}

// USER_INFO flags we care about.
const (
	ufAccountDisable   = 0x0002
	ufPasswdNotreqd    = 0x0020
	ufDontExpirePasswd = 0x10000
	ufNormalAccount    = 0x0200
)

func netUserModalsGet(level uint32) (unsafe.Pointer, error) {
	var buf unsafe.Pointer
	r, _, _ := procNetUserModals.Call(0, uintptr(level), uintptr(unsafe.Pointer(&buf)))
	if r != 0 {
		return nil, syscall.Errno(r)
	}
	return buf, nil
}

func netAPIBufferFree(p unsafe.Pointer) {
	if p != nil {
		_, _, _ = procNetAPIFree.Call(uintptr(p))
	}
}

// passwordPolicy checks local password policy against ECC minimums.
func passwordPolicy(ctx context.Context) []finding.Finding {
	// 2-2-3-1 is "single-factor authentication based on username and password".
	// Password policy strength is evidence toward its implementation (2-2-2);
	// it does not by itself satisfy the control, which is a requirements
	// statement rather than a technical configuration.
	f := finding.New(
		"win.iam.password_policy",
		"Local account password policy",
		"2-2",
		[]string{"2-2-2", "2-2-3-1"},
	)

	buf, err := netUserModalsGet(0)
	if err != nil {
		return []finding.Finding{f.Undetermined(fmt.Errorf("NetUserModalsGet: %w", err))}
	}
	defer netAPIBufferFree(buf)

	p := (*userModalsInfo0)(buf)
	maxAgeDays := "never"
	if p.MaxPasswdAge != timeqForever {
		maxAgeDays = fmt.Sprintf("%d", p.MaxPasswdAge/86400)
	}

	f = f.With("min_password_length", p.MinPasswdLen).
		With("password_history_length", p.PasswordHistLen).
		With("max_password_age_days", maxAgeDays).
		With("min_password_age_days", p.MinPasswdAge/86400)

	problems := passwordPolicyProblems(p.MinPasswdLen, p.PasswordHistLen, p.MaxPasswdAge)

	if len(problems) > 0 {
		return []finding.Finding{f.Failed(
			finding.High,
			"Local password policy is weaker than the expected baseline: "+joinList(problems)+".",
			"Set a minimum password length of at least 8, retain at least 5 previous passwords, and enforce a maximum password age.",
		)}
	}
	return []finding.Finding{f.Passed(fmt.Sprintf(
		"Password policy meets the baseline (minimum length %d, history %d, maximum age %s days).",
		p.MinPasswdLen, p.PasswordHistLen, maxAgeDays,
	))}
}

// lockoutPolicy checks account lockout configuration.
func lockoutPolicy(ctx context.Context) []finding.Finding {
	f := finding.New(
		"win.iam.lockout_policy",
		"Account lockout policy",
		"2-2",
		[]string{"2-2-2", "2-2-3-1"},
	)

	buf, err := netUserModalsGet(3)
	if err != nil {
		return []finding.Finding{f.Undetermined(fmt.Errorf("NetUserModalsGet: %w", err))}
	}
	defer netAPIBufferFree(buf)

	p := (*userModalsInfo3)(buf)
	f = f.With("lockout_threshold", p.LockoutThreshold).
		With("lockout_duration_minutes", p.LockoutDuration/60).
		With("observation_window_minutes", p.LockoutObservationWindow/60)

	if p.LockoutThreshold == 0 {
		return []finding.Finding{f.Failed(
			finding.High,
			"Account lockout is disabled: failed sign-in attempts are unlimited, permitting unrestricted password guessing.",
			"Set an account lockout threshold (commonly 5-10 failed attempts) with a lockout duration of at least 15 minutes.",
		)}
	}
	return []finding.Finding{f.Passed(fmt.Sprintf(
		"Account lockout is enabled at %d failed attempts for %d minutes.",
		p.LockoutThreshold, p.LockoutDuration/60,
	))}
}

// localAccounts inspects local accounts for dormancy, weak flags and
// non-expiring passwords.
func localAccounts(ctx context.Context) []finding.Finding {
	// 2-2-3-5 is "periodic review of identities and access rights" — dormant
	// accounts and non-expiring passwords are direct evidence that such review
	// is not happening. 2-2-3-4 covers privileged access management.
	base := finding.New(
		"win.iam.local_accounts",
		"Local account hygiene",
		"2-2",
		[]string{"2-2-3-4", "2-2-3-5"},
	)

	users, err := enumLocalUsers()
	if err != nil {
		return []finding.Finding{base.Undetermined(fmt.Errorf("NetUserEnum: %w", err))}
	}

	const staleDays = 90
	var (
		enabled       []string
		neverExpires  []string
		noPassword    []string
		stale         []string
		guestEnabled  bool
		now           = time.Now()
		staleCutoffTS = now.AddDate(0, 0, -staleDays).Unix()
	)

	for _, u := range users {
		name := windows.UTF16PtrToString(u.Name)
		if u.Flags&ufAccountDisable != 0 {
			continue
		}
		enabled = append(enabled, name)

		if name == "Guest" {
			guestEnabled = true
		}
		if u.Flags&ufDontExpirePasswd != 0 {
			neverExpires = append(neverExpires, name)
		}
		if u.Flags&ufPasswdNotreqd != 0 {
			noPassword = append(noPassword, name)
		}
		// LastLogon is a Unix timestamp; 0 means the account has never signed in.
		if u.LastLogon != 0 && int64(u.LastLogon) < staleCutoffTS {
			stale = append(stale, name)
		}
	}

	base = base.With("enabled_local_accounts", enabled).
		With("total_local_accounts", len(users))

	var out []finding.Finding

	// Guest account.
	// An enabled Guest account contradicts Need-to-Know and Least Privilege (2-2-3-3).
	g := finding.New("win.iam.guest_account", "Guest account state", "2-2", []string{"2-2-3-3"})
	if guestEnabled {
		out = append(out, g.Failed(
			finding.High,
			"The built-in Guest account is enabled, allowing unauthenticated local access.",
			"Disable the Guest account.",
		))
	} else {
		out = append(out, g.Passed("The built-in Guest account is disabled."))
	}

	// Password-not-required is the most serious of these, so it is reported
	// separately rather than folded into a general hygiene finding.
	if len(noPassword) > 0 {
		// UF_PASSWD_NOTREQD means a blank password is *permitted*, not that one
		// is set. Windows sets this flag by default on several account types,
		// including Microsoft-account-linked ones, so the accurate finding is
		// that policy does not prevent a blank password — claiming the accounts
		// have no password would be a false positive and costs credibility with
		// exactly the reader this report is written for.
		out = append(out, finding.New("win.iam.blank_password_allowed",
			"Accounts permitted to have a blank password", "2-2", []string{"2-2-3-1"}).
			With("accounts", noPassword).
			Failed(finding.High,
				fmt.Sprintf("%d enabled account(s) carry the 'password not required' flag, which permits a blank password to be set: %s. "+
					"This does not confirm the accounts currently have blank passwords.", len(noPassword), joinList(noPassword)),
				"Clear the 'password not required' flag on these accounts so that password policy is enforced for them.",
			))
	}

	switch {
	case len(neverExpires) > 0 || len(stale) > 0:
		detail := ""
		if len(neverExpires) > 0 {
			detail += fmt.Sprintf("%d account(s) have non-expiring passwords (%s). ", len(neverExpires), joinList(neverExpires))
		}
		if len(stale) > 0 {
			detail += fmt.Sprintf("%d account(s) have not signed in for over %d days (%s).", len(stale), staleDays, joinList(stale))
		}
		out = append(out, base.
			With("non_expiring_passwords", neverExpires).
			With("stale_accounts", stale).
			Failed(finding.Medium, detail,
				"Enforce password expiry on all interactive accounts and disable or remove accounts that are no longer in use."))
	default:
		out = append(out, base.Passed(fmt.Sprintf(
			"All %d enabled local account(s) have expiring passwords and recent sign-in activity.", len(enabled))))
	}

	return out
}

// enumLocalUsers returns local accounts via NetUserEnum at level 2,
// filtered to normal user accounts.
func enumLocalUsers() ([]userInfo2, error) {
	const (
		filterNormalAccount = 0x0002
		maxPreferredLength  = 0xFFFFFFFF
	)

	var (
		buf          unsafe.Pointer
		entriesRead  uint32
		totalEntries uint32
		resumeH      uint32
	)

	r, _, _ := procNetUserEnum.Call(
		0, // servername: nil = local
		2, // level
		filterNormalAccount,
		uintptr(unsafe.Pointer(&buf)),
		maxPreferredLength,
		uintptr(unsafe.Pointer(&entriesRead)),
		uintptr(unsafe.Pointer(&totalEntries)),
		uintptr(unsafe.Pointer(&resumeH)),
	)
	if r != 0 {
		return nil, syscall.Errno(r)
	}
	defer netAPIBufferFree(buf)

	out := make([]userInfo2, 0, entriesRead)
	entries := unsafe.Slice((*userInfo2)(buf), entriesRead)
	for _, e := range entries {
		if e.Flags&ufNormalAccount == 0 {
			continue
		}
		// Copy the name out of the API buffer before it is freed.
		cp := e
		nameCopy := windows.StringToUTF16Ptr(windows.UTF16PtrToString(e.Name))
		cp.Name = nameCopy
		out = append(out, cp)
	}
	return out, nil
}
