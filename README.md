# Athar

**أثر** — *the trace left behind; evidence.*

A read-only compliance scanner that produces technical evidence against the
**NCA Essential Cybersecurity Controls (ECC-2:2024)** — the mandatory
cybersecurity framework for Saudi government entities and operators of Critical
National Infrastructure.

It runs locally, makes no network calls, and writes nothing to the host it
scans. What it produces is evidence, not judgement: findings support an
assessor's conclusion rather than replacing it.

## Why you can run this

You are being asked to run a binary against your infrastructure. That deserves
scrutiny, so the design commits to the following and the source is here for you
to check:

- **Read-only.** No configuration is modified. No files are written except the
  report you ask for.
- **Offline.** Zero network calls. A firewall log will show nothing leaving
  the host.
- **No shell.** No PowerShell, no `cmd.exe`, no subprocess execution. Direct
  Windows API and `/proc` reads only, so it works where script execution is
  restricted by policy, AppLocker or WDAC.
- **No credentials handled.** The scanner reads local configuration state. It
  never asks for, stores or transmits a credential.
- **Runs unprivileged.** Most checks need no elevation. The two that do
  (BitLocker volume state, Windows audit policy) report `undetermined` rather
  than guessing when run without it.

## Design principle: never report a false pass

A compliance scanner that misses a problem is unhelpful. One that *confidently
reports a problem does not exist* is dangerous — someone stops looking.

Every check therefore distinguishes four outcomes: `pass`, `fail`, `unknown`
(could not determine, with the reason recorded) and `not_applicable`. The score
counts only conclusive results, so unreadable state can never inflate it.

This is not theoretical. During development, five checks were caught reporting
confident falsehoods only because each was validated against an independent
source — among them a patch-currency check that would have reported a
neglected host as patched today, and a syscall whose `BOOLEAN` return was read
as success when the call had failed.

**Contributions are expected to meet the same bar.** See
[CONTRIBUTING.md](CONTRIBUTING.md).

## Coverage

ECC-2:2024 defines 4 domains, 28 subdomains, 108 controls and 92 subcontrols.

A host scan produces technical evidence for **12 of the 28 subdomains**, citing
**36 of 199 control clauses**. The clause figure is the stricter of the two and
the one an assessor will compute: a subdomain counts as covered when a single
check touches it, even where it contains eight clauses.

The remaining clauses fall into two groups. Some are **not assessable from a
host at all** — governance, policy, contracts, penetration testing, physical
security, business continuity. Others need a vantage point an endpoint does not
have: mail gateway filtering, SPF/DKIM/DMARC (which requires DNS lookups this
scanner deliberately does not make), network segmentation, and network-level
intrusion prevention.

The report lists **all 28 subdomains** regardless, stating the assessment method
each requires, so it accounts for the whole framework rather than only the part
a tool can reach.

ECC controls are written as *requirements* ("shall be identified, documented and
approved"), not as technical configurations. Findings are therefore **evidence
toward** a control, never a verdict on it.

## Tenant connectors

Some ECC clauses cannot be assessed from a host at all, because the evidence
lives in a SaaS tenant: whether MFA is actually *enforced*, whether audit logs
are retained for the twelve months ECC 2-12-3-5 requires, whether information
is classified. `athar-cloud` reads those from Microsoft 365 or Google
Workspace.

```sh
athar-cloud -list                          # checks and the read scopes each needs
athar-cloud -provider m365   -out tenant.json
athar-cloud -provider google -out tenant.json
```

It is a **separate binary on purpose.** The host scanner is offline,
credential-free and read-only; a connector is necessarily none of those.
Keeping them apart means using tenant coverage does not cost you the property
that makes the scanner deployable inside a regulated environment.

The connector holds to what it can:

- **Read-only scopes only**, declared per check so an administrator granting
  consent can see exactly what is read and which control it serves. A test
  fails the build if any check requests a write-capable scope.
- **GET requests only.** There is no code path that writes to a tenant.
- **No credential handling.** The access token is supplied through the
  environment, obtained by the operator with their own tooling (`az`,
  `gcloud`). Credentials are never accepted as flags, because flag values land
  in shell history and the process list.
- **Permission failures are not findings.** A denied scope reports
  `undetermined` and a 404 from an unlicensed feature reports
  `not_applicable` — reporting either as a control failure would tell a
  customer something untrue about their tenant.

## Building

Requires Go 1.26 or later. No cgo, no external build tooling.

```sh
go build -o athar        ./cmd/scanner
go build -o athar-report ./cmd/report
go build -o athar-cloud  ./cmd/athar-cloud

# cross-compile
GOOS=linux   GOARCH=amd64 go build -o athar-linux       ./cmd/scanner
GOOS=linux   GOARCH=arm64 go build -o athar-linux-arm64 ./cmd/scanner
GOOS=windows GOARCH=amd64 go build -o athar.exe         ./cmd/scanner
```

## Usage

```sh
./athar -list                     # list compiled-in checks and their control mappings
./athar -version                  # print version
./athar -out scan.json -fail-on high   # exit 1 if any high or critical finding
./athar-report -in scan.json -out report.html -org "Client Name"

# one report covering a host and a tenant together
./athar-report -in "scan.json,tenant.json" -out report.html -org "Client Name"
```

The scanner emits structured JSON. Rendering is a separate binary so the output
format can change without touching any check. The HTML report is entirely
self-contained — no external stylesheets, fonts or scripts — so it opens on an
air-gapped machine and survives being sent as a single attachment.

## Verification status

| Area | Status |
|---|---|
| Windows checks (37) | Verified on Windows 11, standalone, elevated and unelevated; decision logic unit-tested (12 tests) |
| Windows Server / domain-joined | **Not yet tested** |
| Linux checks (14) | **Parsers unit-tested (15 tests); not yet run on a live host** |
| Total test suite | 38 tests, run on Linux and Windows in CI |
| Cross-compilation | Verified for windows/amd64, linux/amd64, linux/arm64 |
| Tenant connectors (9 checks) | **Logic tested against recorded API responses (11 tests); never run against a live tenant** |

Untested paths are marked as such deliberately. Reports of behaviour on
platforms not listed above are welcome and useful.

## Adding a check

One file per ECC subdomain. Checks register themselves in `init()`, so there is
no central list to edit:

```go
check.Register(check.Check{
    ID:           "win.net.firewall",
    Subdomain:    "2-5",
    ControlCodes: []string{"2-5-2", "2-5-3-5"},
    Platforms:    []string{"windows"},
    Run:          firewallProfiles,
})
```

Control codes are validated against the embedded ECC catalogue at startup. A
check citing a control that does not exist fails the build's smoke test rather
than reaching a customer's report.

## Licence

Apache License 2.0 — see [LICENSE](LICENSE) and [NOTICE](NOTICE).

All dependencies are permissively licensed (BSD-3, MIT). No GPL-family code may
be introduced: this binary is distributed to third parties, and copyleft
obligations would follow it.
