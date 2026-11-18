// Package report renders self-contained offline HTML5 inspection reports
// using auto-escaped Go html/template with zero external network dependencies.
package report

import (
	"bytes"
	"fmt"
	"html/template"
	"strings"

	"github.com/zombat/sonic/internal/redact"
)

const offlineHTMLTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{{.Title}}</title>
<style>
:root{--bg:#0f172a;--card:#1e293b;--fg:#e2e8f0;--muted:#94a3b8;--bd:#334155;--ok:#22c55e;--warn:#f59e0b;--err:#ef4444;--acc:#38bdf8}
@media(prefers-color-scheme:light){:root{--bg:#f8fafc;--card:#ffffff;--fg:#0f172a;--muted:#475569;--bd:#cbd5e1;--acc:#0284c7}}
body{margin:0;padding:24px;font:14px/1.55 system-ui,-apple-system,Segoe UI,Roboto,sans-serif;background:var(--bg);color:var(--fg)}
.wrap{max-width:1120px;margin:0 auto}
.hdr{background:var(--card);border:1px solid var(--bd);border-radius:10px;padding:18px 20px;margin-bottom:16px}
.hdr h1{margin:0 0 6px;font-size:20px}
.meta{color:var(--muted);font-size:13px}
.badge{display:inline-block;padding:2px 8px;border-radius:999px;font-weight:600;font-size:12px;text-transform:uppercase;border:1px solid var(--bd)}
.sev-error,.sev-problem{color:var(--err);border-color:var(--err)}.sev-warning{color:var(--warn);border-color:var(--warn)}.sev-ok,.sev-info{color:var(--ok);border-color:var(--ok)}
.card{background:var(--card);border:1px solid var(--bd);border-radius:10px;padding:16px 20px;margin-bottom:16px;overflow-x:auto}
h2{margin:0 0 12px;font-size:16px;border-bottom:1px solid var(--bd);padding-bottom:6px}
table{width:100%;border-collapse:collapse;font-size:13px}
th,td{text-align:left;padding:7px 8px;border-bottom:1px solid var(--bd);vertical-align:top}
input.flt{width:100%;max-width:340px;padding:6px 10px;margin-bottom:10px;border:1px solid var(--bd);border-radius:6px;background:var(--bg);color:var(--fg)}
pre{margin:0;padding:12px;background:var(--bg);border:1px solid var(--bd);border-radius:8px;overflow:auto;max-height:460px;font:12px/1.45 ui-monospace,SFMono-Regular,Menlo,monospace}
</style>
</head>
<body>
<div class="wrap">
  <div class="hdr">
    <h1>{{.Title}}</h1>
    <div class="meta">
      <span class="badge sev-{{.BadgeClass}}">{{.StatusLabel}}</span>
      {{if .File}} | Capture: <code>{{.File}}</code>{{end}}
      {{if .Protocols}} | Protocols: <code>{{.ProtocolsText}}</code>{{end}}
    </div>
    {{if .Verdict}}<p>{{.Verdict}}</p>{{end}}
  </div>

  {{if .Highlights}}
  <div class="card"><h2>Key Findings &amp; Policy Highlights</h2><ul>{{range .Highlights}}<li>{{.}}</li>{{end}}</ul></div>
  {{end}}

  {{if .Verdicts}}
  <div class="card"><h2>Summary Verdicts</h2><table><thead><tr><th>Section</th><th>Detail</th></tr></thead><tbody>
  {{range .Verdicts}}<tr><td><code>{{.Name}}</code></td><td>{{.Text}}</td></tr>{{end}}
  </tbody></table></div>
  {{end}}

  <div class="card">
    <h2>Issues ({{len .Issues}})</h2>
    <input class="flt" type="search" placeholder="Filter issues by code, detector, or message..." oninput="filterRows('iss-tbl', this.value)">
    <table id="iss-tbl"><thead><tr><th>Severity</th><th>Detector</th><th>Code</th><th>Message</th><th>Frames</th></tr></thead><tbody>
    {{range .Issues}}<tr><td><span class="badge sev-{{.Severity}}">{{.Severity}}</span></td><td><code>{{.Detector}}</code></td><td><code>{{.Code}}</code></td><td>{{.Message}}</td><td>{{fmtInts .Frames}}</td></tr>{{else}}<tr><td colspan="5">No issues recorded.</td></tr>{{end}}
    </tbody></table>
  </div>

  {{if .Timeline}}
  <div class="card">
    <h2>Timeline ({{len .Timeline}})</h2>
    <table id="tl-tbl"><thead><tr><th>Time (s)</th><th>Protocol</th><th>Event</th><th>Detail</th></tr></thead><tbody>
    {{range .Timeline}}<tr><td><code>{{.T}}</code></td><td><code>{{.Protocol}}</code></td><td><code>{{.Event}}</code></td><td>{{.Detail}}</td></tr>{{end}}
    </tbody></table>
  </div>
  {{end}}

  {{if .Audit}}
  <div class="card"><h2>Redaction Audit</h2>
    <p>Total masked items: <strong>{{.Audit.Total}}</strong> (known secrets: {{.Audit.KnownSecrets}}, auth headers: {{.Audit.AuthHeaders}}, PEM: {{.Audit.PEMBlocks}}, JWTs: {{.Audit.JWTs}}, tokens: {{.Audit.ProviderTokens}}, Bearer/Basic: {{.Audit.BearerTokens}}/{{.Audit.BasicAuth}}, assignments: {{.Audit.Assignments}}, SDP keys: {{.Audit.SDPKeys}}).</p>
  </div>
  {{end}}

  <div class="card"><h2>Redacted Raw JSON</h2><pre>{{.PrettyJSON}}</pre></div>
</div>
<script>
function filterRows(id,q){var f=q.toLowerCase(),rows=document.querySelectorAll('#'+id+' tbody tr');for(var i=0;i<rows.length;i++){rows[i].style.display=rows[i].textContent.toLowerCase().indexOf(f)>=0?'':'none';}}
</script>
</body>
</html>
`

var parsedHTMLTmpl = template.Must(template.New("sonic_html").Funcs(template.FuncMap{
	"fmtInts": FormatInts,
}).Parse(offlineHTMLTemplate))

type htmlViewData struct {
	ReportDigest
	BadgeClass    string
	StatusLabel   string
	ProtocolsText string
}

// RenderHTMLReport generates a self-contained offline HTML5 report from any S.O.N.I.C. JSON payload.
func RenderHTMLReport(title string, rawJSON []byte, audit *redact.AuditCounts) (string, error) {
	digest, err := ParseReportDigest(title, rawJSON, audit)
	if err != nil {
		return "", err
	}
	status := digest.OverallStatus
	if status == "" {
		status = digest.Status
	}
	if status == "" {
		status = "info"
	}
	vd := htmlViewData{
		ReportDigest:  digest,
		BadgeClass:    strings.ToLower(status),
		StatusLabel:   StatusMark(status),
		ProtocolsText: strings.Join(digest.Protocols, ", "),
	}
	var buf bytes.Buffer
	if err := parsedHTMLTmpl.Execute(&buf, vd); err != nil {
		return "", fmt.Errorf("render html report: %w", err)
	}
	return buf.String(), nil
}

// SaveHTMLReport renders and writes a redacted offline HTML5 report to path.
func SaveHTMLReport(path, title string, rawJSON []byte, audit *redact.AuditCounts) error {
	htmlDoc, err := RenderHTMLReport(title, rawJSON, audit)
	if err != nil {
		return err
	}
	return WriteRedacted(path, htmlDoc)
}
