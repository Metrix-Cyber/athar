# Contributing

## The one rule that matters

**Never report a false pass.**

A check that misses something is a gap. A check that reports a problem does not
exist is a liability, because someone stops looking. If a check cannot
determine an answer, it must return `finding.Unknown` with the reason — never
`Pass`.

Every check in this repository was validated against an independent source
before being merged. Five were caught reporting confident falsehoods that way:

| Defect | How it would have failed |
|---|---|
| `AuditQuerySystemPolicy` returns `BOOLEAN`, one byte; the return register held garbage in its upper bits | A failed call read as success, then dereferenced a nil pointer |
| Patch currency fell back to the `WindowsUpdate` key timestamp | Touched by update *checks*, so a neglected host reports as patched today |
| `ProductName` still reads "Windows 10" on Windows 11 | Asset inventory naming the wrong operating system |
| `Enrollments` carries ~30 stub entries with a `ProviderID` | An unmanaged laptop reported as centrally MDM-managed |
| `UF_PASSWD_NOTREQD` described as "may sign in without a password" | Overstated: the flag permits a blank password, it does not set one |

None of these were visible by reading the code. All were found by comparing
output against `netstat`, `dsregcmd`, `Get-LocalGroupMember`,
`Get-BitLockerVolume` or `Win32_OperatingSystem`.

## Before submitting a check

1. **Verify against an independent source** on a real host, and say which one in
   the pull request. "It looked right" is not verification.
2. **Cite a real control.** Control codes are validated against the embedded
   ECC catalogue at startup; an unknown code exits with status 2.
3. **Phrase findings precisely.** Describe what was observed, not what it
   implies. If a registry flag *permits* something, do not write that it *is*
   the case.
4. **Handle absence explicitly.** On Windows, a missing value often means "OS
   default", which differs by build. Distinguish "explicitly configured",
   "explicitly disabled" and "not configured" rather than inferring.
5. **Prefer syscalls to shelling out.** No `os/exec`. Environments that block
   script execution are exactly the environments this tool targets.
6. **Resolve identities by SID, not by name.** Group and account names are
   localised; `"Administrators"` does not exist on an Arabic-language Windows
   install, and a name lookup would silently find nothing and report a clean
   result.

## Linux checks

Parsing logic lives in `internal/checks/linux/parse.go`, which carries **no
build constraint** so it compiles and is tested on any development machine.
Only registration and live filesystem reads are Linux-only.

Parsers take content as a string rather than reading files themselves. This is
what makes fixture-based testing possible, and it is required: contributors on
Windows cannot otherwise exercise this code at all.

Add fixtures for the cases that would silently produce wrong findings, not just
the happy path. Existing tests cover OpenSSH's first-occurrence-wins directive
semantics, little-endian `/proc/net` addresses, and distribution-varying
`UID_MIN` — each of which produces a plausible-looking wrong answer if handled
naively.

## Licensing

Contributions are accepted under the Apache License 2.0.

**No GPL, LGPL or AGPL dependencies.** This binary is distributed to third
parties, so copyleft obligations would follow that distribution. Permissive
licences only: Apache-2.0, MIT, BSD.

## Checks

```sh
go vet ./...
go test ./...
go build ./...
```
