//go:build windows

package windows

import (
	"context"
	"fmt"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/Metrix-Cyber/athar/internal/check"
	"github.com/Metrix-Cyber/athar/internal/finding"
)

// ECC 2-2-3-4 is "Privileged access management"; 2-2-3-3 covers authorization
// on Least Privilege principles.
var privCodes = []string{"2-2-3-3", "2-2-3-4"}

func init() {
	for _, c := range []check.Check{
		{ID: "win.priv.local_administrators", Subdomain: "2-2", ControlCodes: privCodes,
			Platforms: []string{"windows"}, Run: localAdministrators},
		{ID: "win.priv.uac", Subdomain: "2-2", ControlCodes: privCodes,
			Platforms: []string{"windows"}, Run: uacConfiguration},
	} {
		check.Register(c)
	}
}

var procNetLocalGroupGetMembers = netapi32.NewProc("NetLocalGroupGetMembers")

// localGroupMembersInfo2 mirrors LOCALGROUP_MEMBERS_INFO_2.
type localGroupMembersInfo2 struct {
	SID       uintptr
	SIDUsage  uint32
	DomainAnd *uint16
}

// localAdministrators enumerates the built-in Administrators group.
//
// The group is resolved by its well-known RID rather than by the name
// "Administrators", which is localised — on an Arabic-language Windows
// install, a name lookup would silently find nothing and the check would
// report a clean result on a host it never actually examined. That matters
// directly for the target market.
func localAdministrators(ctx context.Context) []finding.Finding {
	f := finding.New("win.priv.local_administrators",
		"Local Administrators group membership", "2-2", privCodes)

	group, err := builtinAdminGroupName()
	if err != nil {
		return []finding.Finding{f.Undetermined(err)}
	}
	f = f.With("group_name", group)

	members, err := localGroupMembers(group)
	if err != nil {
		return []finding.Finding{f.Undetermined(
			fmt.Errorf("enumerating %q: %w", group, err))}
	}

	f = f.With("members", members).With("member_count", len(members))

	// A threshold rather than a rule: what counts as excessive depends on the
	// host's role, so this surfaces the membership for assessor judgement
	// instead of asserting a hard limit.
	const reviewThreshold = 3
	if len(members) > reviewThreshold {
		return []finding.Finding{f.Failed(finding.Medium,
			fmt.Sprintf("The local Administrators group has %d members: %s. Privileged access should be limited to those requiring it, with administrative work performed through separate named accounts.",
				len(members), joinList(members)),
			"Review each member against need, remove those that do not require local administrative rights, and evidence periodic review of privileged access.")}
	}

	return []finding.Finding{f.Passed(fmt.Sprintf(
		"The local Administrators group has %d member(s): %s. Membership should still be confirmed against the entity's privileged access register.",
		len(members), joinList(members)))}
}

// builtinAdminGroupName resolves the built-in Administrators group from its
// well-known SID (S-1-5-32-544), returning its localised name.
func builtinAdminGroupName() (string, error) {
	sid, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		return "", fmt.Errorf("resolving built-in Administrators SID: %w", err)
	}
	name, _, _, err := sid.LookupAccount("")
	if err != nil {
		return "", fmt.Errorf("looking up Administrators group name: %w", err)
	}
	return name, nil
}

// localGroupMembers returns the account names in a local group.
func localGroupMembers(group string) ([]string, error) {
	g, err := windows.UTF16PtrFromString(group)
	if err != nil {
		return nil, err
	}

	var (
		buf         unsafe.Pointer
		entriesRead uint32
		total       uint32
		resume      uintptr
	)

	const (
		level              = 2
		maxPreferredLength = 0xFFFFFFFF
	)

	r, _, _ := procNetLocalGroupGetMembers.Call(
		0, // local server
		uintptr(unsafe.Pointer(g)),
		level,
		uintptr(unsafe.Pointer(&buf)),
		maxPreferredLength,
		uintptr(unsafe.Pointer(&entriesRead)),
		uintptr(unsafe.Pointer(&total)),
		uintptr(unsafe.Pointer(&resume)),
	)
	if r != 0 {
		return nil, syscall.Errno(r)
	}
	defer netAPIBufferFree(buf)

	out := make([]string, 0, entriesRead)
	for _, m := range unsafe.Slice((*localGroupMembersInfo2)(buf), entriesRead) {
		if m.DomainAnd != nil {
			out = append(out, windows.UTF16PtrToString(m.DomainAnd))
		}
	}
	return out, nil
}

const policySystem = `SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`

// uacConfiguration checks User Account Control, which gates privilege
// elevation on the host.
func uacConfiguration(ctx context.Context) []finding.Finding {
	f := finding.New("win.priv.uac", "User Account Control", "2-2", privCodes)

	enabled, _, err := dwordOr(policySystem, "EnableLUA", 1)
	if err != nil {
		return []finding.Finding{f.Undetermined(err)}
	}
	f = f.With("uac_enabled", enabled == 1)

	if enabled != 1 {
		return []finding.Finding{f.Failed(finding.High,
			"User Account Control is disabled. Processes started by administrative users run fully elevated without prompting, so any code they launch inherits administrative rights silently.",
			"Enable User Account Control (EnableLUA = 1) and restart the host.")}
	}

	// ConsentPromptBehaviorAdmin: 0 elevates without prompting, which
	// undermines UAC while leaving it nominally enabled.
	consent, present, err := dwordOr(policySystem, "ConsentPromptBehaviorAdmin", 5)
	if err != nil {
		return []finding.Finding{f.Undetermined(err)}
	}
	f = f.With("consent_prompt_behavior_admin", consent).With("policy_configured", present)

	if consent == 0 {
		return []finding.Finding{f.Failed(finding.High,
			"User Account Control is enabled but administrators are elevated without any prompt, which defeats the control in practice.",
			"Set the administrator elevation prompt to require consent or credentials on the secure desktop.")}
	}

	// Secure desktop isolates the prompt from other processes.
	secure, _, _ := dwordOr(policySystem, "PromptOnSecureDesktop", 1)
	f = f.With("prompt_on_secure_desktop", secure == 1)
	if secure != 1 {
		return []finding.Finding{f.Failed(finding.Medium,
			"User Account Control prompts are not shown on the secure desktop, allowing other running software to interact with or obscure the elevation prompt.",
			"Enable 'Switch to the secure desktop when prompting for elevation'.")}
	}

	return []finding.Finding{f.Passed(
		"User Account Control is enabled, prompts administrators for elevation, and uses the secure desktop.")}
}
