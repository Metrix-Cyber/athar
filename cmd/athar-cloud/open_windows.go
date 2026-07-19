//go:build windows

package main

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	kernel32                  = windows.NewLazySystemDLL("kernel32.dll")
	procGetConsoleProcessList = kernel32.NewProc("GetConsoleProcessList")
)

// openURL asks Windows to open an address with the default browser.
//
// ShellExecute is used rather than starting cmd.exe: it asks the shell to open
// a target with its registered handler, so no command interpreter is involved
// and nothing in the URL is ever parsed as a command.
func openURL(target string) error {
	verb, err := windows.UTF16PtrFromString("open")
	if err != nil {
		return err
	}
	u, err := windows.UTF16PtrFromString(target)
	if err != nil {
		return err
	}
	return windows.ShellExecute(0, verb, u, nil, nil, windows.SW_SHOWNORMAL)
}

// launchedByDoubleClick reports whether the program owns its console, which is
// true when started from a file manager and false when run from a shell or a
// pipeline. Guided mode must not engage in the latter case: it would block a
// script waiting for a keypress that never comes.
// Windows attaches every process sharing a console to that console's process
// list. A binary launched from a shell shares the shell's console, so the list
// holds at least two entries; one launched from Explorer gets a console of its
// own, so the list holds exactly one.
func launchedByDoubleClick() bool {
	var pids [4]uint32
	r, _, _ := procGetConsoleProcessList.Call(
		uintptr(unsafe.Pointer(&pids[0])), uintptr(len(pids)))
	return r == 1
}
