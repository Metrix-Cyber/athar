//go:build !windows

package main

import (
	"os/exec"
	"runtime"
)

// openURL hands an address to the desktop's default handler.
//
// Unlike the host scanner, this connector needs a browser to exist: the sign-in
// flow has nowhere to happen without one. A failure is therefore reported
// rather than ignored, so the caller can print the address for the operator to
// open themselves.
func openURL(target string) error {
	var cmd string
	switch runtime.GOOS {
	case "darwin":
		cmd = "open"
	default:
		cmd = "xdg-open"
	}
	return exec.Command(cmd, target).Start()
}

// launchedByDoubleClick is always false away from Windows. There is no
// file-manager launch convention for a terminal binary, and a mode that waited
// for input would hang any script that ran this without arguments.
func launchedByDoubleClick() bool { return false }
