package main

import "html/template"

// No scripts, no external stylesheets, no fonts, no CDN. A security tool that
// fetches resources from the internet to draw its own interface is asking the
// reader to trust something they cannot inspect — and this one is meant to run
// on hosts with no route to the internet at all.

const uiStyle = `
<style>
  :root {
    color-scheme: light dark;
    --bg:#f6f7f9; --card:#fff; --ink:#16181d; --muted:#5c6370;
    --line:#e3e6ea; --accent:#1f6feb;
    --crit:#b42318; --high:#c4530a; --med:#8a6d00; --low:#4a5568; --ok:#1a7f45;
  }
  @media (prefers-color-scheme: dark) {
    :root { --bg:#14161a; --card:#1c1f25; --ink:#e8eaed; --muted:#9aa3ad;
            --line:#2b2f36; --accent:#5a9bff;
            --crit:#f0736a; --high:#f0a35e; --med:#d9c05a; --low:#98a3b3; --ok:#5fd48c; }
  }
  * { box-sizing: border-box; }
  body { margin:0; background:var(--bg); color:var(--ink);
         font:15px/1.55 system-ui,-apple-system,"Segoe UI",sans-serif; }
  header { background:var(--card); border-bottom:1px solid var(--line); padding:1.1rem 2rem; }
  .brand { display:flex; align-items:baseline; gap:.6rem; }
  .brand b { font-size:1.15rem; letter-spacing:.02em; }
  .brand span { color:var(--muted); font-size:.85rem; }
  main { max-width:78rem; margin:0 auto; padding:2rem; }
  h1 { font-size:1.5rem; margin:0 0 .25rem; }
  h2 { font-size:1.05rem; margin:2.5rem 0 .75rem; }
  .sub { color:var(--muted); margin:0 0 1.5rem; }

  .cards { display:grid; grid-template-columns:repeat(auto-fit,minmax(9rem,1fr)); gap:1rem; }
  .card { background:var(--card); border:1px solid var(--line); border-radius:10px; padding:1.1rem 1.25rem; }
  .card .n { font-size:2rem; font-weight:600; line-height:1.1; }
  .card .l { color:var(--muted); font-size:.85rem; margin-top:.15rem; }
  .card.crit .n{color:var(--crit)} .card.high .n{color:var(--high)}
  .card.med .n{color:var(--med)}  .card.low .n{color:var(--low)}
  .card.ok .n{color:var(--ok)}

  .bar { height:6px; border-radius:3px; background:var(--line); overflow:hidden; margin-top:.6rem; }
  .bar i { display:block; height:100%; background:var(--accent); }

  table { width:100%; border-collapse:collapse; background:var(--card);
          border:1px solid var(--line); border-radius:10px; overflow:hidden; }
  th { text-align:left; font-size:.78rem; text-transform:uppercase; letter-spacing:.04em;
       color:var(--muted); padding:.7rem 1rem; border-bottom:1px solid var(--line); font-weight:600; }
  td { padding:.85rem 1rem; border-bottom:1px solid var(--line); vertical-align:top; }
  tr:last-child td { border-bottom:none; }
  .sev { display:inline-block; padding:.12rem .5rem; border-radius:4px; font-size:.75rem;
         font-weight:600; text-transform:uppercase; letter-spacing:.03em; border:1px solid; }
  .sev.critical{color:var(--crit);border-color:var(--crit)}
  .sev.high{color:var(--high);border-color:var(--high)}
  .sev.medium{color:var(--med);border-color:var(--med)}
  .sev.low{color:var(--low);border-color:var(--low)}
  .ttl { font-weight:600; }
  .dt { color:var(--muted); font-size:.9rem; margin-top:.2rem; }
  .fix { font-size:.9rem; margin-top:.45rem; padding-left:.7rem; border-left:2px solid var(--accent); }
  code { background:rgba(128,128,128,.15); padding:.08rem .3rem; border-radius:3px; font-size:.85em; }

  button, .btn { font:inherit; font-weight:500; padding:.6rem 1.3rem; border-radius:7px;
                 border:1px solid var(--line); background:var(--card); color:var(--ink);
                 cursor:pointer; text-decoration:none; display:inline-block; }
  .btn.primary, button.primary { background:var(--accent); border-color:var(--accent); color:#fff; }
  .row { display:flex; gap:.7rem; flex-wrap:wrap; align-items:center; }
  .note { background:var(--card); border:1px solid var(--line); border-left:3px solid var(--high);
          border-radius:8px; padding:.9rem 1.1rem; margin:1.25rem 0; font-size:.93rem; }
  .muted { color:var(--muted); font-size:.9rem; }
  details summary { cursor:pointer; color:var(--muted); margin:1.5rem 0 .5rem; }
</style>`

const uiHeader = `<header><div class="brand"><b>ATHAR</b>
<span>NCA ECC&#8209;2:2024 host assessment</span></div></header>`

// pageReady is what the reader sees first: what will run, on what, and one
// button. Anything else here is noise in front of the only action available.
var pageReady = template.Must(template.New("ready").Parse(`<!doctype html>
<meta charset="utf-8"><title>Athar</title>` + uiStyle + uiHeader + `
<main>
  <h1>Assess this computer</h1>
  <p class="sub">{{.Checks}} read&#8209;only checks against NCA ECC&#8209;2:2024 on <b>{{.Host}}</b>.
     Nothing is changed, nothing leaves this machine.</p>

  {{if not .Elevated}}
  <div class="note"><b>Not running as administrator.</b>
    Two checks cannot be read without it and will report as undetermined.
    To include them, close this, right&#8209;click Athar and choose
    <b>Run as administrator</b>.</div>
  {{end}}

  <form method="post" action="/scan">
    <button class="primary" type="submit">Run the assessment</button>
  </form>
  <p class="muted" style="margin-top:1rem">Takes a few seconds. The page will
     refresh with the results.</p>
</main>`))

var pageResults = template.Must(template.New("results").Parse(`<!doctype html>
<meta charset="utf-8"><title>Athar — {{.Host}}</title>` + uiStyle + uiHeader + `
<main>
  <h1>{{.Host}}</h1>
  <p class="sub">{{.OS}} · assessed in {{.Duration}}{{if not .Elevated}} · not elevated{{end}}</p>

  <div class="cards">
    <div class="card"><div class="n">{{.Summary.Total}}</div><div class="l">checks run</div></div>
    <div class="card ok"><div class="n">{{.Summary.Pass}}</div><div class="l">passed</div></div>
    <div class="card crit"><div class="n">{{.Summary.Fail}}</div><div class="l">need attention</div></div>
    {{if .Summary.Unknown}}<div class="card"><div class="n">{{.Summary.Unknown}}</div><div class="l">undetermined</div></div>{{end}}
    <div class="card">
      <div class="n">{{.Coverage}}%</div>
      <div class="l">{{.Summary.ClausesCited}} of {{.Summary.ClausesTotal}} clauses</div>
      <div class="bar"><i style="width:{{.Coverage}}%"></i></div>
    </div>
  </div>

  {{if .Summary.Fail}}
  <div class="cards" style="margin-top:1rem">
    {{if .Critical}}<div class="card crit"><div class="n">{{.Critical}}</div><div class="l">critical</div></div>{{end}}
    {{if .High}}<div class="card high"><div class="n">{{.High}}</div><div class="l">high</div></div>{{end}}
    {{if .Medium}}<div class="card med"><div class="n">{{.Medium}}</div><div class="l">medium</div></div>{{end}}
    {{if .Low}}<div class="card low"><div class="n">{{.Low}}</div><div class="l">low</div></div>{{end}}
  </div>
  {{end}}

  {{if .Reports}}
  <h2>Formal report</h2>
  <div class="row">
    {{range .Reports}}<a class="btn primary" href="/report?framework={{.ID}}" target="_blank">{{.Name}}</a>{{end}}
  </div>
  <p class="muted" style="margin-top:.7rem">Saved to <code>{{.Dir}}</code> alongside the raw findings as JSON.</p>
  {{end}}

  {{if .Failed}}
  <h2>Needs attention — {{len .Failed}}</h2>
  <table>
    <tr><th style="width:6.5rem">Severity</th><th>Finding</th><th style="width:11rem">ECC clause</th></tr>
    {{range .Failed}}
    <tr>
      <td><span class="sev {{.Severity}}">{{.Severity}}</span></td>
      <td>
        <div class="ttl">{{.Title}}</div>
        <div class="dt">{{.Detail}}</div>
        {{if .Remediation}}<div class="fix">{{.Remediation}}</div>{{end}}
      </td>
      <td><code>{{.Codes}}</code><div class="dt">{{.Subdomain}}</div></td>
    </tr>
    {{end}}
  </table>
  {{end}}

  {{if .Undetermined}}
  <h2>Could not be determined — {{len .Undetermined}}</h2>
  <p class="muted">These are not failures. The value could not be read, usually
     because the assessment is not running as administrator.</p>
  <table>
    <tr><th>Finding</th><th style="width:11rem">ECC clause</th></tr>
    {{range .Undetermined}}
    <tr><td><div class="ttl">{{.Title}}</div>
            {{if .Err}}<div class="dt">{{.Err}}</div>{{end}}</td>
        <td><code>{{.Codes}}</code></td></tr>
    {{end}}
  </table>
  {{end}}

  {{if .Passed}}
  <details>
    <summary>{{len .Passed}} checks passed — show</summary>
    <table>
      <tr><th>Finding</th><th style="width:11rem">ECC clause</th></tr>
      {{range .Passed}}
      <tr><td><div class="ttl">{{.Title}}</div><div class="dt">{{.Detail}}</div></td>
          <td><code>{{.Codes}}</code></td></tr>
      {{end}}
    </table>
  </details>
  {{end}}

  <h2>Before you share this</h2>
  <p class="muted">This page lists exploitable weaknesses on a specific machine.
     Treat it as confidential.</p>

  <div class="row" style="margin-top:1.5rem">
    <form method="post" action="/scan"><button type="submit">Run again</button></form>
    <form method="post" action="/quit"><button type="submit">Finish</button></form>
  </div>
</main>`))

var pageClosedScan = template.Must(template.New("closed").Parse(`<!doctype html>
<meta charset="utf-8"><title>Athar</title>` + uiStyle + uiHeader + `
<main><h1>Finished</h1>
<p class="sub">Your reports are saved. You can close this tab.</p></main>`))
