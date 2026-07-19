package main

import "html/template"

// Pages are deliberately plain: no scripts, no external stylesheets, no fonts.
// A security tool that pulls resources from the internet to render its own
// interface is asking an administrator to trust something they cannot inspect,
// and the Content-Security-Policy this is served with forbids it anyway.

const style = `
<style>
  :root { color-scheme: light dark; }
  body { font: 16px/1.6 system-ui, -apple-system, Segoe UI, sans-serif;
         max-width: 46rem; margin: 3rem auto; padding: 0 1.5rem; }
  h1 { font-size: 1.5rem; margin-bottom: .25rem; }
  h2 { font-size: 1.05rem; margin-top: 2rem; }
  .sub { opacity: .7; margin-top: 0; }
  fieldset { border: 1px solid rgba(128,128,128,.35); border-radius: 8px;
             padding: 1rem 1.25rem; margin: 1.25rem 0; }
  legend { padding: 0 .4rem; font-weight: 600; }
  label { display: block; margin: .5rem 0; }
  input[type=text] { width: 100%; padding: .55rem .7rem; font: inherit;
                     border: 1px solid rgba(128,128,128,.5); border-radius: 6px;
                     background: transparent; color: inherit; }
  button { font: inherit; padding: .6rem 1.2rem; border-radius: 6px;
           border: 1px solid rgba(128,128,128,.5); cursor: pointer;
           background: rgba(128,128,128,.12); color: inherit; }
  code { background: rgba(128,128,128,.15); padding: .1rem .35rem; border-radius: 4px;
         font-size: .9em; word-break: break-all; }
  ol { padding-left: 1.2rem; } li { margin: .35rem 0; }
  .scopes { font-size: .9rem; opacity: .85; }
  .num { font-size: 2rem; font-weight: 600; margin: 0; }
  .row { display: flex; gap: 2.5rem; margin: 1.5rem 0; }
  .warn { border-left: 3px solid #c77; padding-left: 1rem; }
  .muted { opacity: .7; font-size: .92rem; }
</style>`

var pageHome = template.Must(template.New("home").Parse(`<!doctype html>
<meta charset="utf-8"><title>Athar Cloud</title>` + style + `
<h1>Athar Cloud</h1>
<p class="sub">Assess a Microsoft 365 or Google Workspace tenant against NCA ECC&#8209;2:2024.</p>

<p>This reads your tenant's configuration and produces a report. It only ever
reads &mdash; it issues no request that can change anything.</p>

<form method="post" action="/start">
  <fieldset>
    <legend>Microsoft 365</legend>
    <label><input type="radio" name="provider" value="m365" checked> Assess a Microsoft 365 tenant</label>
    <label>Application (client) ID
      <input type="text" name="client_id_m365" value="{{.M365ClientID}}"
             placeholder="00000000-0000-0000-0000-000000000000"></label>
    <p class="scopes">Permissions requested, all read&#8209;only:
      {{range $i, $s := .M365Scopes}}{{if $i}}, {{end}}<code>{{$s}}</code>{{end}}</p>
  </fieldset>

  <fieldset>
    <legend>Google Workspace</legend>
    <label><input type="radio" name="provider" value="google"> Assess a Google Workspace domain</label>
    <label>OAuth client ID
      <input type="text" name="client_id_google" value="{{.GoogleClientID}}"
             placeholder="000000000000-xxxxxxxx.apps.googleusercontent.com"></label>
    <p class="scopes">Permissions requested, all read&#8209;only:
      {{range $i, $s := .GoogleScopes}}{{if $i}}, {{end}}<code>{{$s}}</code>{{end}}</p>
  </fieldset>

  <button type="submit">Sign in and assess</button>
</form>

<h2>First time: register an application</h2>
<p>Athar signs in as you, using an application registered in your own tenant, so
the consent screen names your organisation rather than a third party. This is
done once.</p>
<ol>
  <li>Open the Azure portal &rarr; <b>Microsoft Entra ID</b> &rarr; <b>App registrations</b> &rarr; <b>New registration</b>.</li>
  <li>Name it anything. Under <b>Supported account types</b> choose
      <b>Accounts in this organizational directory only</b>.</li>
  <li>Under <b>Redirect URI</b> select <b>Public client/native</b> and enter:<br>
      <code>{{.Redirect}}</code></li>
  <li>Register, then copy the <b>Application (client) ID</b> into the box above.</li>
  <li>Go to <b>API permissions</b> &rarr; <b>Add a permission</b> &rarr; <b>Microsoft Graph</b> &rarr;
      <b>Delegated permissions</b>, and add each permission listed above.</li>
  <li>Click <b>Grant admin consent</b>. Without this the sign-in succeeds but
      the checks report "undetermined" rather than a result.</li>
</ol>

<p class="muted warn">The redirect address changes every time this program runs,
because it uses whichever local port is free. Enter it in the app registration
as shown &mdash; Entra accepts any <code>http://127.0.0.1</code> port for a
public client, so you only need to do this once.</p>

<h2>First time: Google Workspace</h2>
<p>Google does not accept an arbitrary loopback port, so the address below must
be entered exactly, and re&#8209;entered if it changes.</p>
<ol>
  <li>Open the Google Cloud console &rarr; <b>APIs &amp; Services</b> &rarr; <b>Credentials</b>
      &rarr; <b>Create credentials</b> &rarr; <b>OAuth client ID</b>.</li>
  <li>Application type: <b>Web application</b>.</li>
  <li>Under <b>Authorised redirect URIs</b> add:<br><code>{{.Redirect}}</code></li>
  <li>Copy the <b>Client ID</b> into the box above.</li>
  <li>Under <b>Enabled APIs</b>, enable the <b>Admin SDK API</b>. Without it the
      directory checks cannot run at all.</li>
  <li>Sign in as a Workspace <b>super administrator</b>. The Admin SDK returns
      nothing to an ordinary account, which reports as "undetermined".</li>
</ol>

<p class="muted">Nothing is stored except the application ID, which is not a
secret. No token is written to disk; it is discarded when this program closes.</p>
`))

var pageDone = template.Must(template.New("done").Parse(`<!doctype html>
<meta charset="utf-8"><title>Assessment complete — Athar Cloud</title>` + style + `
<h1>Assessment complete</h1>
<p class="sub">{{.Provider}}{{if .Tenant}} — {{.Tenant}}{{end}}</p>

<div class="row">
  <div><p class="num">{{.Pass}}</p><div>passed</div></div>
  <div><p class="num">{{.Fail}}</p><div>need attention</div></div>
  {{if .Unknown}}<div><p class="num">{{.Unknown}}</p><div>undetermined</div></div>{{end}}
</div>

{{if .Unknown}}
<p class="warn">Undetermined findings almost always mean a permission was not
granted. Open the app registration, confirm every listed permission is present,
and click <b>Grant admin consent</b>.</p>
{{end}}

<h2>Your report</h2>
<p>Written to <code>{{.Dir}}</code>:</p>
<ul>
  <li><code>{{.HTML}}</code> — the report</li>
  <li><code>{{.JSON}}</code> — the same findings as data</li>
</ul>
<p class="muted">The report describes weaknesses in a live tenant. Treat it as
confidential and review it before sharing.</p>

<form method="post" action="/quit"><button type="submit">Close</button></form>
`))

var pageError = template.Must(template.New("error").Parse(`<!doctype html>
<meta charset="utf-8"><title>Athar Cloud</title>` + style + `
<h1>{{.Headline}}</h1>
{{if .Detail}}<p>{{.Detail}}</p>{{end}}
<p><a href="/">Start again</a></p>
`))

var pageClosed = template.Must(template.New("closed").Parse(`<!doctype html>
<meta charset="utf-8"><title>Athar Cloud</title>` + style + `
<h1>Finished</h1>
<p>You can close this tab.</p>
`))
