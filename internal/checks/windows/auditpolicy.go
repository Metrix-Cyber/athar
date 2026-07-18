//go:build windows

package windows

import (
	"context"
	"fmt"
	"sort"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/Metrix-Cyber/athar/internal/check"
	"github.com/Metrix-Cyber/athar/internal/finding"
)

func init() {
	for _, c := range []check.Check{
		{ID: "win.log.audit_policy", Subdomain: "2-12", ControlCodes: logCodes,
			Platforms: []string{"windows"}, NeedsAdmin: true, Run: auditPolicy},
		{ID: "win.epp.screen_lock", Subdomain: "2-3", ControlCodes: malwareCodes,
			Platforms: []string{"windows"}, Run: screenLock},
	} {
		check.Register(c)
	}
}

var (
	advapi32                   = windows.NewLazySystemDLL("advapi32.dll")
	procAuditQuerySystemPolicy = advapi32.NewProc("AuditQuerySystemPolicy")
	procAuditFree              = advapi32.NewProc("AuditFree")
)

// auditPolicyInformation mirrors AUDIT_POLICY_INFORMATION.
type auditPolicyInformation struct {
	AuditSubCategoryGUID windows.GUID
	AuditingInformation  uint32
	AuditCategoryGUID    windows.GUID
}

// Audit policy bits.
const (
	auditSuccess = 0x1
	auditFailure = 0x2
)

// booleanTrue interprets the return value of a Win32 function declared as
// BOOLEAN.
//
// BOOLEAN is a single byte, not a 4-byte BOOL. The syscall return register
// carries unrelated data in its upper bytes, so comparing the full uintptr
// against zero treats failures as successes — which here meant dereferencing
// a nil output pointer and panicking inside a customer's report. Mask to the
// low byte for any BOOLEAN-returning function.
func booleanTrue(r uintptr) bool { return r&0xFF != 0 }

// auditSubcategory identifies a subcategory to require, with the GUID Windows
// uses for it. ECC 2-12-3-1 and 2-12-3-2 require event logging for critical
// assets and for privileged account access.
type auditSubcategory struct {
	name        string
	guid        windows.GUID
	needSuccess bool
	needFailure bool
}

// The subcategories below are those without which a security log cannot
// evidence privileged access or account misuse.
var requiredAudit = []auditSubcategory{
	{"Logon", windows.GUID{Data1: 0x0cce9215, Data2: 0x69ae, Data3: 0x11d9,
		Data4: [8]byte{0xbe, 0xd3, 0x50, 0x50, 0x54, 0x50, 0x30, 0x30}}, true, true},
	{"Logoff", windows.GUID{Data1: 0x0cce9216, Data2: 0x69ae, Data3: 0x11d9,
		Data4: [8]byte{0xbe, 0xd3, 0x50, 0x50, 0x54, 0x50, 0x30, 0x30}}, true, false},
	{"Special Logon", windows.GUID{Data1: 0x0cce921b, Data2: 0x69ae, Data3: 0x11d9,
		Data4: [8]byte{0xbe, 0xd3, 0x50, 0x50, 0x54, 0x50, 0x30, 0x30}}, true, false},
	{"User Account Management", windows.GUID{Data1: 0x0cce9235, Data2: 0x69ae, Data3: 0x11d9,
		Data4: [8]byte{0xbe, 0xd3, 0x50, 0x50, 0x54, 0x50, 0x30, 0x30}}, true, true},
	{"Security Group Management", windows.GUID{Data1: 0x0cce9237, Data2: 0x69ae, Data3: 0x11d9,
		Data4: [8]byte{0xbe, 0xd3, 0x50, 0x50, 0x54, 0x50, 0x30, 0x30}}, true, true},
	{"Process Creation", windows.GUID{Data1: 0x0cce922b, Data2: 0x69ae, Data3: 0x11d9,
		Data4: [8]byte{0xbe, 0xd3, 0x50, 0x50, 0x54, 0x50, 0x30, 0x30}}, true, false},
	{"Audit Policy Change", windows.GUID{Data1: 0x0cce922f, Data2: 0x69ae, Data3: 0x11d9,
		Data4: [8]byte{0xbe, 0xd3, 0x50, 0x50, 0x54, 0x50, 0x30, 0x30}}, true, true},
}

// auditPolicy reports which security audit subcategories are active.
//
// AuditQuerySystemPolicy requires SeSecurityPrivilege, so unelevated this
// reports undetermined rather than guessing. Audit configuration cannot be
// inferred from the registry on modern Windows, where advanced audit policy
// supersedes the legacy settings.
func auditPolicy(ctx context.Context) []finding.Finding {
	f := finding.New("win.log.audit_policy", "Security audit policy", "2-12", logCodes)

	guids := make([]windows.GUID, len(requiredAudit))
	for i, s := range requiredAudit {
		guids[i] = s.guid
	}

	var policies *auditPolicyInformation
	r, _, err := procAuditQuerySystemPolicy.Call(
		uintptr(unsafe.Pointer(&guids[0])),
		uintptr(len(guids)),
		uintptr(unsafe.Pointer(&policies)),
	)
	if !booleanTrue(r) {
		return []finding.Finding{f.Undetermined(fmt.Errorf(
			"security audit policy requires administrative privileges to read; "+
				"re-run the scan elevated to assess audit configuration (%v)", err))}
	}

	// A success return with a nil buffer has been observed in practice. Never
	// dereference the API's output without checking it: a panic here would
	// otherwise surface to the customer as a stack trace inside their
	// compliance report.
	if policies == nil {
		return []finding.Finding{f.Undetermined(fmt.Errorf(
			"audit policy query reported success but returned no data (%v)", err))}
	}
	defer procAuditFree.Call(uintptr(unsafe.Pointer(policies)))

	results := unsafe.Slice(policies, len(requiredAudit))

	var missing []string
	for i, s := range requiredAudit {
		info := results[i].AuditingInformation
		on := info&auditSuccess != 0
		if s.needFailure {
			on = on && info&auditFailure != 0
		}
		f = f.With("audit_"+s.name, describeAudit(info))
		if !on {
			missing = append(missing, s.name)
		}
	}
	sort.Strings(missing)

	if len(missing) > 0 {
		return []finding.Finding{f.With("subcategories_not_configured", missing).
			Failed(finding.High,
				fmt.Sprintf("%d security audit subcategor(ies) are not fully enabled: %s. Without them the security log cannot evidence privileged account use or changes to accounts and audit configuration.",
					len(missing), joinList(missing)),
				"Enable success and failure auditing for logon, account management, process creation and audit policy change subcategories by Group Policy.")}
	}

	return []finding.Finding{f.Passed(
		"All required security audit subcategories are enabled.")}
}

func describeAudit(info uint32) string {
	switch {
	case info&auditSuccess != 0 && info&auditFailure != 0:
		return "success and failure"
	case info&auditSuccess != 0:
		return "success only"
	case info&auditFailure != 0:
		return "failure only"
	default:
		return "not configured"
	}
}

// screenLock checks that an unattended session locks automatically.
func screenLock(ctx context.Context) []finding.Finding {
	f := finding.New("win.epp.screen_lock", "Automatic session lock", "2-3", malwareCodes)

	const desktopPolicy = `SOFTWARE\Policies\Microsoft\Windows\Control Panel\Desktop`

	timeoutStr, err := regString(desktopPolicy, "ScreenSaveTimeOut")
	secure, _ := regString(desktopPolicy, "ScreenSaverIsSecure")
	active, _ := regString(desktopPolicy, "ScreenSaveActive")

	if err != nil {
		// Absent policy means the setting is left to each user, which is not
		// evidence of an enforced lock.
		return []finding.Finding{f.With("policy_configured", false).
			Failed(finding.Medium,
				"No enforced automatic session lock policy was found. Unattended workstations may remain unlocked indefinitely, leaving authenticated sessions available to anyone with physical access.",
				"Enforce a screen lock by Group Policy with a timeout of 15 minutes or less and require a password on resume.")}
	}

	f = f.With("screen_save_timeout_seconds", timeoutStr).
		With("password_protected", secure == "1").
		With("screen_saver_active", active == "1").
		With("policy_configured", true)

	timeout := buildNumber(timeoutStr)
	const maxSeconds = 900 // 15 minutes

	switch {
	case secure != "1":
		return []finding.Finding{f.Failed(finding.Medium,
			"A screen saver timeout is configured but it does not require a password on resume, so the session is not actually locked.",
			"Enable 'Password protect the screen saver' alongside the timeout.")}
	case timeout == 0 || timeout > maxSeconds:
		return []finding.Finding{f.Failed(finding.Low,
			fmt.Sprintf("The enforced session lock timeout is %s seconds, longer than the 15 minutes commonly required for unattended workstations.", timeoutStr),
			"Reduce the automatic lock timeout to 15 minutes (900 seconds) or less.")}
	default:
		return []finding.Finding{f.Passed(fmt.Sprintf(
			"Sessions lock automatically after %d seconds and require a password on resume.", timeout))}
	}
}
