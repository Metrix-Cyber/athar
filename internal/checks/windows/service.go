//go:build windows

package windows

import (
	"fmt"

	"golang.org/x/sys/windows"
)

// serviceState reports whether a Windows service is running.
//
// The service control manager is opened with SC_MANAGER_CONNECT and the
// service with SERVICE_QUERY_STATUS only. Requesting the full access rights
// that the convenience wrappers use would require elevation, and a check that
// silently needs admin is a check that reports "undetermined" on every real
// user's machine.
func serviceState(name string) (running bool, present bool, err error) {
	scm, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT)
	if err != nil {
		return false, false, fmt.Errorf("opening service control manager: %w", err)
	}
	defer windows.CloseServiceHandle(scm)

	svcName, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return false, false, err
	}

	h, err := windows.OpenService(scm, svcName, windows.SERVICE_QUERY_STATUS)
	if err != nil {
		// A missing service is a meaningful answer, not a failure.
		return false, false, nil
	}
	defer windows.CloseServiceHandle(h)

	var status windows.SERVICE_STATUS
	if err := windows.QueryServiceStatus(h, &status); err != nil {
		return false, true, fmt.Errorf("querying %s: %w", name, err)
	}
	return status.CurrentState == windows.SERVICE_RUNNING, true, nil
}
