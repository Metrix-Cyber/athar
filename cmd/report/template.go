package main

// htmlTemplate is the report layout. Everything is inline — no external
// stylesheets, fonts or scripts — so the file renders identically on an
// air-gapped host and survives being forwarded as a single attachment.
const htmlTemplate = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Cybersecurity Compliance Assessment — {{.Report.Host.Hostname}}</title>
<style>
  :root {
    --bg: #ffffff; --fg: #14181f; --muted: #5c6672; --line: #e3e7ec;
    --panel: #f7f9fb; --crit: #b3261e; --high: #c2571a; --med: #9a7000;
    --low: #4a5568; --pass: #1e7a4c; --accent: #123a5e;
  }
  @media (prefers-color-scheme: dark) {
    :root {
      --bg: #12161b; --fg: #e6eaef; --muted: #97a1ad; --line: #2a323b;
      --panel: #1a2027; --crit: #ff6b5e; --high: #ff9d52; --med: #e0b64a;
      --low: #9aa5b1; --pass: #4ec98a; --accent: #7fb3e0;
    }
  }
  * { box-sizing: border-box; }
  body {
    margin: 0; padding: 32px 24px 64px; background: var(--bg); color: var(--fg);
    font: 15px/1.6 -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
  }
  .wrap { max-width: 900px; margin: 0 auto; }
  header { border-bottom: 2px solid var(--accent); padding-bottom: 20px; margin-bottom: 28px; }
  .brand { font-size: 13px; letter-spacing: .08em; text-transform: uppercase; color: var(--muted); }
  h1 { font-size: 25px; margin: 8px 0 4px; font-weight: 650; }
  .sub { color: var(--muted); font-size: 14px; }
  .meta { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 14px; margin-top: 20px; }
  .meta div { font-size: 13px; }
  .meta dt { color: var(--muted); margin-bottom: 2px; }
  .meta dd { margin: 0; font-weight: 550; }

  .cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: 12px; margin: 24px 0; }
  .card { background: var(--panel); border: 1px solid var(--line); border-radius: 8px; padding: 14px 16px; }
  .card .n { font-size: 26px; font-weight: 680; line-height: 1.1; }
  .card .l { font-size: 12px; color: var(--muted); text-transform: uppercase; letter-spacing: .05em; margin-top: 4px; }
  .n.crit { color: var(--crit); } .n.high { color: var(--high); }
  .n.med { color: var(--med); } .n.low { color: var(--low); } .n.ok { color: var(--pass); }

  .notice { background: var(--panel); border-left: 3px solid var(--accent); padding: 14px 16px;
            border-radius: 0 6px 6px 0; margin: 24px 0; font-size: 14px; color: var(--muted); }
  .notice strong { color: var(--fg); }

  h2 { font-size: 15px; margin: 34px 0 6px; padding-bottom: 6px; border-bottom: 1px solid var(--line); }
  h2 .code { color: var(--muted); font-weight: 500; }
  h2 .tag { float: right; font-size: 12px; font-weight: 500; color: var(--crit); }

  .f { border: 1px solid var(--line); border-radius: 8px; padding: 14px 16px; margin: 12px 0; }
  .f.fail { border-left: 3px solid var(--crit); }
  .f.fail.high { border-left-color: var(--high); }
  .f.fail.med  { border-left-color: var(--med); }
  .f.fail.low  { border-left-color: var(--low); }
  .f.pass { border-left: 3px solid var(--pass); }
  .f.unknown { border-left: 3px solid var(--muted); }
  .f h3 { font-size: 15px; margin: 0 0 6px; font-weight: 600; }
  .badge { display: inline-block; font-size: 11px; font-weight: 650; letter-spacing: .05em;
           text-transform: uppercase; padding: 2px 7px; border-radius: 4px; margin-right: 8px;
           border: 1px solid currentColor; }
  .badge.crit { color: var(--crit); } .badge.high { color: var(--high); }
  .badge.med { color: var(--med); } .badge.low { color: var(--low); }
  .badge.info { color: var(--pass); }
  .f p { margin: 6px 0; }
  .fix { font-size: 14px; color: var(--fg); background: var(--panel); border-radius: 6px;
         padding: 10px 12px; margin-top: 10px; }
  .fix b { display: block; font-size: 11px; text-transform: uppercase; letter-spacing: .05em;
           color: var(--muted); margin-bottom: 4px; }
  .codes { font-size: 12px; color: var(--muted); margin-top: 8px; font-variant-numeric: tabular-nums; }
  details { margin-top: 10px; }
  summary { cursor: pointer; font-size: 13px; color: var(--muted); }
  pre { background: var(--panel); border: 1px solid var(--line); border-radius: 6px;
        padding: 10px 12px; overflow-x: auto; font-size: 12.5px; margin: 8px 0 0;
        font-family: ui-monospace, "Cascadia Code", Consolas, monospace; }
  .gap { background: var(--panel); border: 1px dashed var(--line); border-radius: 8px;
         padding: 12px 14px; margin: 12px 0; font-size: 14px; color: var(--muted); }
  .gap.partial-note { border-style: solid; border-left: 3px solid var(--accent);
                      margin-bottom: 16px; }
  .lvl { display: inline-block; font-size: 10.5px; font-weight: 700; letter-spacing: .06em;
         text-transform: uppercase; padding: 2px 7px; border-radius: 4px; margin-right: 9px;
         border: 1px solid currentColor; vertical-align: 1px; }
  .lvl.documentary { color: var(--med); }
  .lvl.assessor    { color: var(--high); }
  .lvl.partial     { color: var(--accent); }
  footer { margin-top: 48px; padding-top: 16px; border-top: 1px solid var(--line);
           font-size: 12px; color: var(--muted); }
</style>
</head>
<body>
<div class="wrap">

<header>
  <div class="brand">{{.Brand}} — NCA ECC-2:2024 Assessment</div>
  <h1>Cybersecurity Compliance Assessment</h1>
  <div class="sub">{{if .Org}}{{.Org}} — {{end}}Host {{.Report.Host.Hostname}}</div>
  <dl class="meta">
    <div><dt>Generated</dt><dd>{{.Generated}}</dd></div>
    <div><dt>Operating system</dt><dd>{{.Report.Host.OS}} {{.Report.Host.Version}} ({{.Report.Host.Arch}})</dd></div>
    <div><dt>Framework</dt><dd>{{.Report.Framework}}</dd></div>
    <div><dt>Scanner version</dt><dd>{{.Report.ScannerVersion}}</dd></div>
  </dl>
</header>

<div class="cards">
  <div class="card"><div class="n {{if .HasFail}}crit{{else}}ok{{end}}">{{.Score}}%</div>
       <div class="l">Checks passed</div></div>
  <div class="card"><div class="n ok">{{.Report.Summary.Pass}}</div><div class="l">Passing</div></div>
  <div class="card"><div class="n crit">{{.Report.Summary.Fail}}</div><div class="l">Failing</div></div>
  {{range .SevOrdered}}
  <div class="card"><div class="n {{.Class}}">{{.Count}}</div><div class="l">{{.Name}}</div></div>
  {{end}}
</div>

<div class="notice">
  <strong>Scope of this assessment.</strong>
  This automated scan produced technical evidence for {{.Coverage}} ECC-2:2024 subdomains,
  from {{.Assessed}} conclusive checks on this host — citing
  <strong>{{.Report.Summary.ClausesCited}} of {{.Report.Summary.ClausesTotal}} control
  clauses</strong>. Subdomain coverage is the more favourable figure of the two, because a
  subdomain counts as covered when a single check touches it; the clause count is the
  stricter measure and is stated here for that reason.
  <strong>All 28 subdomains are listed below.</strong> The {{.Remaining}} not evidenced by
  this scan are shown with the assessment method each requires — these are policy,
  documentary and organisational controls that no host scan can verify, and they are
  included so this report accounts for the whole framework rather than only its
  technically assessable part.
  {{if not .Report.Elevated}}
  This scan ran <strong>without administrative privileges</strong>; some checks could not
  be fully determined and are marked accordingly.
  {{end}}
  <br><br>
  ECC-2:2024 controls are written as requirements to be identified, documented, approved
  and implemented — not as technical configurations. Each result below is therefore
  <strong>evidence toward</strong> the referenced control, not a verdict on it. A passing
  technical check supports an assessor's conclusion; it does not replace one.
</div>

<div class="notice apply">
  <strong>Applying these settings — {{.ApplyTitle}}.</strong>
  {{.ApplyGuidance}}
</div>

{{range .Groups}}
<h2>
  <span class="code">{{.Code}}</span> &nbsp; {{.Name}}
  {{if .Fails}}<span class="tag">{{.Fails}} failing</span>{{end}}
</h2>

{{if not .Findings}}
<div class="gap">
  <span class="lvl {{.Level}}">{{.Level}}</span>
  {{.Reason}}
</div>
{{else if ne .Level "automated"}}
<div class="gap partial-note">
  <span class="lvl {{.Level}}">{{.Level}}</span>
  {{.Reason}}
</div>
{{end}}

{{range .Findings}}
<div class="f {{.Status}} {{sevClass .Severity}}">
  <h3>{{.Title}}</h3>
  <div>
    {{if eq (printf "%s" .Status) "fail"}}<span class="badge {{sevClass .Severity}}">{{.Severity}}</span>
    {{else if eq (printf "%s" .Status) "pass"}}<span class="badge info">Pass</span>
    {{else}}<span class="badge">{{.Status}}</span>{{end}}
  </div>
  <p>{{.Detail}}</p>
  {{if .Err}}<p><em>Could not determine: {{.Err}}</em></p>{{end}}
  {{if .Remediation}}<div class="fix"><b>Recommended action</b>{{.Remediation}}</div>{{end}}
  {{with evidence .Evidence}}
  <details><summary>Evidence</summary><pre>{{.}}</pre></details>
  {{end}}
  <div class="codes">Evidence toward ECC control{{if gt (len .ControlCodes) 1}}s{{end}}:
    {{range $i, $c := .ControlCodes}}{{if $i}}, {{end}}{{$c}}{{end}}
    &nbsp;·&nbsp; check <code>{{.CheckID}}</code></div>
</div>
{{end}}
{{end}}

<footer>
  Generated by {{.Brand}} compliance scanner {{.Report.ScannerVersion}} on {{.Generated}}.
  Findings reflect the state of {{.Report.Host.Hostname}} at scan time and are evidence for
  assessment, not a certification of compliance.
</footer>

</div>
</body>
</html>
`
