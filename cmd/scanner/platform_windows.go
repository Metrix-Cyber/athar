//go:build windows

package main

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"

	"github.com/Metrix-Cyber/athar/internal/check"
)

var (
	kernel32                  = windows.NewLazySystemDLL("kernel32.dll")
	procGetConsoleProcessList = kernel32.NewProc("GetConsoleProcessList")
)

// launchedByDoubleClick reports whether this process owns its console window.
//
// Absence of arguments is not a reliable signal: `athar.exe > scan.json` also
// has no arguments, and treating that as a double-click produced an empty file
// instead of a report — a shell user's redirection silently hijacked.
//
// Windows attaches every process sharing a console to that console's process
// list. A binary launched from cmd or PowerShell shares the shell's console,
// so the list holds at least two entries. A binary launched from Explorer gets
// a console created for it alone, so the list holds exactly one.
func launchedByDoubleClick() bool {
	var pids [4]uint32
	r, _, _ := procGetConsoleProcessList.Call(
		uintptr(unsafe.Pointer(&pids[0])),
		uintptr(len(pids)),
	)
	// A zero return means the call failed — no console at all, for instance
	// under a service or a redirected pipe. Treat that as "not interactive"
	// rather than guessing.
	return r == 1
}

// isElevated reports whether the process holds an elevated token. Checks that
// need elevation degrade to "undetermined" rather than failing silently, and
// the report records this so a clean-looking scan cannot be mistaken for a
// complete one.
func isElevated() bool {
	return windows.GetCurrentProcessToken().IsElevated()
}

func osVersion() string {
	v := windows.RtlGetVersion()
	return fmt.Sprintf("%d.%d.%d", v.MajorVersion, v.MinorVersion, v.BuildNumber)
}

const cvKey = `SOFTWARE\Microsoft\Windows NT\CurrentVersion`

// edition returns the Windows edition identifier (Core, Professional,
// Enterprise, ServerStandard, ...). It determines whether the Local Group
// Policy Editor is available, which matters for remediation advice: Home
// editions have no gpedit.msc, so settings must be applied another way.
func edition() string {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, cvKey, registry.QUERY_VALUE)
	if err != nil {
		return ""
	}
	defer k.Close()
	v, _, _ := k.GetStringValue("EditionID")
	return v
}

// management determines how this host's configuration is administered.
func management(ed string) check.Management {
	m := check.Management{}

	if k, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SYSTEM\CurrentControlSet\Services\Tcpip\Parameters`, registry.QUERY_VALUE); err == nil {
		m.Domain, _, _ = k.GetStringValue("Domain")
		k.Close()
		m.DomainJoined = m.Domain != ""
	}

	// Azure AD (Entra) device join.
	if k, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SYSTEM\CurrentControlSet\Control\CloudDomainJoin\JoinInfo`,
		registry.ENUMERATE_SUB_KEYS); err == nil {
		if names, _ := k.ReadSubKeyNames(-1); len(names) > 0 {
			m.CloudJoined = true
		}
		k.Close()
	}

	m.MDMProviders = enrolledMDMProviders()

	switch {
	case len(m.MDMProviders) > 0:
		m.Mode = "mdm"
	case m.DomainJoined:
		m.Mode = "domain"
	case ed == "Core" || ed == "CoreSingleLanguage" || ed == "CoreN":
		// Home editions ship without the Local Group Policy Editor.
		m.Mode = "standalone"
	default:
		m.Mode = "local-policy"
	}
	return m
}

// mdmDeviceEnrollmentTypes are the EnrollmentType values denoting genuine
// device management: 6 is standard MDM device enrolment, 13 is enrolment via
// an Azure AD joined device.
var mdmDeviceEnrollmentTypes = map[uint64]bool{6: true, 13: true}

// enrolledMDMProviders returns providers actually managing this device.
//
// Windows ships roughly thirty stub entries under Enrollments on every
// installation, several carrying a ProviderID ("MEMDM", "Local Authority",
// "Cloud Authority"). Treating any ProviderID as enrolment reports an
// unmanaged home machine as centrally managed — verified against dsregcmd,
// which reported no domain, no Azure AD join and no MDM URL on exactly such a
// host. A real enrolment carries a device EnrollmentType and a discovery URL
// pointing at the managing service.
func enrolledMDMProviders() []string {
	const enrollments = `SOFTWARE\Microsoft\Enrollments`

	k, err := registry.OpenKey(registry.LOCAL_MACHINE, enrollments, registry.ENUMERATE_SUB_KEYS)
	if err != nil {
		return nil
	}
	names, _ := k.ReadSubKeyNames(-1)
	k.Close()

	var out []string
	for _, n := range names {
		sk, err := registry.OpenKey(registry.LOCAL_MACHINE, enrollments+`\`+n, registry.QUERY_VALUE)
		if err != nil {
			continue
		}
		provider, _, _ := sk.GetStringValue("ProviderID")
		enrollType, _, _ := sk.GetIntegerValue("EnrollmentType")
		url, _, _ := sk.GetStringValue("DiscoveryServiceFullURL")
		if url == "" {
			url, _, _ = sk.GetStringValue("MdmUrl")
		}
		sk.Close()

		if provider != "" && url != "" && mdmDeviceEnrollmentTypes[enrollType] {
			out = append(out, provider)
		}
	}
	return out
}
