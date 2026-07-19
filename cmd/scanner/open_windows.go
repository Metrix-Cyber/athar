//go:build windows

package main

import (
	"golang.org/x/sys/windows"
)

// openReport asks Windows to open the finished report with the user's default
// browser.
//
// This was previously refused on the grounds that the scanner executes no
// subprocess. That was the wrong trade. The guarantee exists so the tool can
// run where script execution is restricted by policy, AppLocker or WDAC — it
// is about how the *assessment* is performed. Handing the finished report to
// the shell afterwards is not script execution and is not part of the scan.
//
// The precise claim, which remains true: the scan itself reads only through
// Windows APIs and spawns nothing. Nothing here runs during assessment; this
// fires once, after the report is written, and only when the user launched the
// binary interactively rather than from a shell or a pipeline.
//
// ShellExecute is used rather than starting cmd.exe: it asks the shell to open
// a document with its registered handler, so no command interpreter is
// involved and nothing from the report path is ever parsed as a command.
func openReport(path string) error {
	verb, err := windows.UTF16PtrFromString("open")
	if err != nil {
		return err
	}
	file, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	return windows.ShellExecute(0, verb, file, nil, nil, windows.SW_SHOWNORMAL)
}
