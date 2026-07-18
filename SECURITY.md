# Security Policy

## Reporting a vulnerability

Please report security issues privately rather than opening a public issue.
Use GitHub's private vulnerability reporting on this repository, or contact the
maintainers directly.

Please include what you did, what happened, and what you expected. A proof of
concept helps but is not required.

## Scope

This project is a read-only scanner that runs on hosts it assesses, so the
security properties that matter most are:

**Anything that writes to the scanned host.** The scanner must not modify
configuration, create files outside its own report output, or alter any
security setting. A change to a host under assessment is a serious defect.

**Anything that leaves the host.** The scanner makes no network calls. A
dependency or code path that transmits data anywhere is a serious defect.

**Anything that executes.** There is no subprocess execution, no shell
invocation, and no interpretation of external input as code. Findings and
evidence are data.

**Command injection through evidence.** Findings can contain values read from
the host — hostnames, account names, file paths. These are rendered into HTML
reports. Escaping failures that permit script injection into a report are in
scope.

**Privilege handling.** The scanner requests no privileges it does not need.
Checks requiring elevation must degrade to `undetermined` rather than failing
open or requesting elevation implicitly.

## Reporting accuracy

Incorrect findings are not vulnerabilities, but a check that reports a **false
pass** — asserting a control is satisfied when it is not — is treated with the
same seriousness, because it can cause an organisation to stop looking at a real
exposure. Report those the same way.

## Supported versions

This project is pre-1.0. Security fixes are applied to the main branch.
