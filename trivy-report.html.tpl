<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Trivy Security Report</title>
  <style>
    :root {
      --critical: #c62828;
      --high: #e65100;
      --medium: #f9a825;
      --low: #2e7d32;
      --unknown: #616161;
      --secret: #6a1b9a;
      --kev: #b71c1c;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; background: #f5f5f5; color: #212121; }

    header { background: #1a237e; color: white; padding: 1.5rem 2rem; }
    header h1 { font-size: 1.4rem; font-weight: 600; }
    header p { opacity: .7; font-size: .85rem; margin-top: .3rem; }

    .summary { display: flex; gap: 1rem; padding: 1.25rem 2rem; background: white; border-bottom: 1px solid #e0e0e0; }
    .card { flex: 1; border-radius: 8px; padding: .9rem 1.25rem; color: white; text-align: center; }
    .card .count { font-size: 2.2rem; font-weight: 700; line-height: 1; }
    .card .label { font-size: .75rem; text-transform: uppercase; letter-spacing: .06em; margin-top: .3rem; opacity: .9; }
    .card-critical { background: var(--critical); }
    .card-high     { background: var(--high); }
    .card-medium   { background: var(--medium); color: #212121; }
    .card-low      { background: var(--low); }
    .card-secret   { background: var(--secret); }
    .card-kev      { background: var(--kev); }

    .filters { padding: .75rem 2rem; background: white; display: flex; gap: .5rem; border-bottom: 1px solid #e0e0e0; align-items: center; flex-wrap: wrap; }
    .filters span { font-size: .85rem; color: #757575; margin-right: .25rem; }
    .filters button {
      padding: .35rem .9rem; border: 2px solid #e0e0e0; border-radius: 20px;
      cursor: pointer; font-size: .82rem; font-weight: 600; background: white; color: #424242;
      transition: all .15s;
    }
    .filters button:hover { border-color: #9fa8da; }
    .filters button.active { border-color: #1a237e; background: #e8eaf6; color: #1a237e; }
    .filters button#btn-KEV.active { border-color: var(--kev); background: #fdecea; color: var(--kev); }
    .filters select {
      padding: .35rem .75rem; border: 2px solid #e0e0e0; border-radius: 20px;
      font-size: .82rem; font-weight: 600; background: white; color: #424242;
      cursor: pointer; max-width: 320px;
    }
    .filters .divider { width: 1px; height: 1.4rem; background: #e0e0e0; margin: 0 .5rem; }

    .content { padding: 1.5rem 2rem; }

    .target-group {
      background: white; border-radius: 8px; margin-bottom: 1.25rem;
      box-shadow: 0 1px 3px rgba(0,0,0,.1); overflow: hidden;
    }
    .target-header {
      background: #37474f; color: white; padding: .85rem 1.25rem;
      display: flex; align-items: center; gap: .75rem; cursor: pointer; user-select: none;
    }
    .target-header:hover { background: #455a64; }
    .target-header.secret-header { background: #4a148c; }
    .target-header.secret-header:hover { background: #6a1b9a; }
    .target-toggle { font-size: .8rem; transition: transform .2s; display: inline-block; }
    .target-group.collapsed .target-toggle { transform: rotate(-90deg); }
    .target-group.collapsed table { display: none; }
    .target-name {
      font-family: 'SFMono-Regular', Consolas, monospace; font-size: .9rem;
      font-weight: 600; flex: 1; word-break: break-all;
    }
    .target-type, .target-class {
      font-size: .7rem; text-transform: uppercase; letter-spacing: .05em;
      padding: .2rem .55rem; border-radius: 4px;
    }
    .target-type  { background: rgba(255,255,255,.15); }
    .target-class { background: rgba(255,255,255,.08); opacity: .85; }
    .target-counts { display: flex; gap: .35rem; }
    .target-counts .badge { font-size: .68rem; padding: .15rem .45rem; }

    table { width: 100%; border-collapse: collapse; }
    th { padding: .65rem 1rem; text-align: left; font-size: .72rem; text-transform: uppercase;
         letter-spacing: .06em; white-space: nowrap; background: #eceff1; color: #455a64;
         border-bottom: 1px solid #cfd8dc; }
    td { padding: .7rem 1rem; font-size: .88rem; border-bottom: 1px solid #f5f5f5; vertical-align: top; }
    tbody tr:last-child td { border-bottom: none; }
    tbody tr:hover { background: #fafafa; }
    tr.row-hidden { display: none; }

    .badge { display: inline-block; padding: .2rem .55rem; border-radius: 4px; font-size: .72rem; font-weight: 700; color: white; white-space: nowrap; }
    .badge-CRITICAL { background: var(--critical); }
    .badge-HIGH     { background: var(--high); }
    .badge-MEDIUM   { background: var(--medium); color: #212121; }
    .badge-LOW      { background: var(--low); }
    .badge-UNKNOWN  { background: var(--unknown); }
    .badge-SECRET   { background: var(--secret); }
    .badge-kev      { background: var(--kev); cursor: help; }

    .pkg-name { font-weight: 600; font-family: 'SFMono-Regular', Consolas, monospace; font-size: .82rem; white-space: nowrap; }
    .pkg-path { font-size: .72rem; color: #757575; font-family: 'SFMono-Regular', Consolas, monospace;
                margin-top: .2rem; word-break: break-all; max-width: 280px; }
    .cve-id   { font-family: 'SFMono-Regular', Consolas, monospace; font-size: .82rem; white-space: nowrap; }
    .vuln-title { max-width: 260px; font-size: .84rem; color: #424242; }
    .version  { font-family: 'SFMono-Regular', Consolas, monospace; font-size: .82rem; white-space: nowrap; }

    .epss { font-family: 'SFMono-Regular', Consolas, monospace; font-size: .82rem; white-space: nowrap; text-align: center; color: #757575; }
    .epss-high { color: var(--critical); font-weight: 700; }
    .epss-med  { color: var(--high); font-weight: 600; }
    .epss-low  { color: #9e9e9e; }
    .kev { text-align: center; }
    .kev-none { color: #bdbdbd; }

    .links a { display: block; font-size: .75rem; color: #1565c0; word-break: break-all; margin-bottom: .15rem; }
    .toggle-links {
      margin-top: .2rem; font-size: .75rem; color: #1565c0; cursor: pointer;
      background: none; border: none; padding: 0; text-decoration: underline;
    }
    .empty { text-align: center; padding: 3rem; color: #9e9e9e; font-size: .95rem; background: white; border-radius: 8px; }
    .target-group.all-hidden { display: none; }
  </style>
</head>
<body>

<header>
  <h1>Trivy Security Report</h1>
  <p id="report-date"></p>
</header>

<div class="summary">
  <div class="card card-critical"><div class="count" id="cnt-CRITICAL">0</div><div class="label">Critical</div></div>
  <div class="card card-high">    <div class="count" id="cnt-HIGH">0</div>    <div class="label">High</div></div>
  <div class="card card-medium">  <div class="count" id="cnt-MEDIUM">0</div>  <div class="label">Medium</div></div>
  <div class="card card-low">     <div class="count" id="cnt-LOW">0</div>     <div class="label">Low</div></div>
  <div class="card card-kev">     <div class="count" id="cnt-KEV">0</div>     <div class="label">KEV</div></div>
  <div class="card card-secret">  <div class="count" id="cnt-SECRET">0</div>  <div class="label">Secrets</div></div>
</div>

<div class="filters">
  <span>Severity:</span>
  <button class="active" id="btn-ALL"      onclick="setFilter('ALL')">All</button>
  <button              id="btn-CRITICAL" onclick="setFilter('CRITICAL')">Critical</button>
  <button              id="btn-HIGH"     onclick="setFilter('HIGH')">High</button>
  <button              id="btn-MEDIUM"   onclick="setFilter('MEDIUM')">Medium</button>
  <button              id="btn-LOW"      onclick="setFilter('LOW')">Low</button>
  <span class="divider"></span>
  <button              id="btn-KEV"      onclick="toggleKev()">KEV only</button>
  <span style="margin-left:1.5rem;">Source:</span>
  <select id="target-filter" onchange="setTargetFilter(this.value)">
    <option value="ALL">All sources</option>
  </select>
</div>

<div class="content" id="content">
  {{- $hasContent := false -}}
  {{- range . -}}
    {{- if .Vulnerabilities -}}
      {{- $hasContent = true -}}
      {{- $result := . -}}
      {{- $crit := 0 -}}{{- $high := 0 -}}{{- $med := 0 -}}{{- $low := 0 -}}
      {{- range .Vulnerabilities -}}
        {{- if eq .Severity "CRITICAL" }}{{- $crit = add $crit 1 -}}{{- end -}}
        {{- if eq .Severity "HIGH"     }}{{- $high = add $high 1 -}}{{- end -}}
        {{- if eq .Severity "MEDIUM"   }}{{- $med  = add $med  1 -}}{{- end -}}
        {{- if eq .Severity "LOW"      }}{{- $low  = add $low  1 -}}{{- end -}}
      {{- end }}
      <div class="target-group" data-target="{{ escapeXML $result.Target }}">
        <div class="target-header" onclick="this.parentElement.classList.toggle('collapsed')">
          <span class="target-toggle">▼</span>
          <span class="target-name">{{ escapeXML $result.Target }}</span>
          {{- if $result.Type }}<span class="target-type">{{ $result.Type }}</span>{{- end -}}
          {{- if $result.Class }}<span class="target-class">{{ $result.Class }}</span>{{- end }}
          <span class="target-counts">
            {{- if gt $crit 0 }}<span class="badge badge-CRITICAL">{{ $crit }} C</span>{{- end -}}
            {{- if gt $high 0 }}<span class="badge badge-HIGH">{{ $high }} H</span>{{- end -}}
            {{- if gt $med  0 }}<span class="badge badge-MEDIUM">{{ $med }} M</span>{{- end -}}
            {{- if gt $low  0 }}<span class="badge badge-LOW">{{ $low }} L</span>{{- end }}
          </span>
        </div>
        <table>
          <thead>
            <tr>
              <th>Package</th>
              <th>CVE / ID</th>
              <th>Title</th>
              <th>Severity</th>
              <th style="text-align:center">EPSS</th>
              <th style="text-align:center">KEV</th>
              <th>Installed</th>
              <th>Fixed in</th>
              <th>References</th>
            </tr>
          </thead>
          <tbody>
            {{- range .Vulnerabilities }}
            <tr data-severity="{{ .Severity }}" data-kind="vuln" data-target="{{ escapeXML $result.Target }}" data-kev="{{ if .Custom }}{{ if .Custom.KEV }}true{{ end }}{{ end }}">
              <td>
                <div class="pkg-name">{{ escapeXML .PkgName }}</div>
                {{- if .PkgPath }}<div class="pkg-path">{{ escapeXML .PkgPath }}</div>{{- end }}
              </td>
              <td class="cve-id">{{ .VulnerabilityID }}</td>
              <td class="vuln-title">{{ escapeXML .Title }}</td>
              <td><span class="badge badge-{{ .Severity }}">{{ .Severity }}</span></td>
              <td class="epss {{ if .Custom }}{{ .Custom.EPSSClass }}{{ end }}">{{ if .Custom }}{{ .Custom.EPSS }}{{ else }}-{{ end }}</td>
              <td class="kev">{{- if .Custom }}{{- if .Custom.KEV }}<span class="badge badge-kev"{{ if .Custom.KEVDueDate }} title="Échéance CISA : {{ .Custom.KEVDueDate }}"{{ end }}>KEV</span>{{- else }}<span class="kev-none">—</span>{{- end }}{{- else }}<span class="kev-none">—</span>{{- end -}}</td>
              <td class="version">{{ escapeXML .InstalledVersion }}</td>
              <td class="version">{{ escapeXML .FixedVersion }}</td>
              <td class="links">
                {{- range .References }}<a href="{{ . }}" target="_blank" rel="noopener">{{ . }}</a>{{- end }}
              </td>
            </tr>
            {{- end }}
          </tbody>
        </table>
      </div>
    {{- end -}}
    {{- if .Secrets -}}
      {{- $hasContent = true -}}
      {{- $result := . -}}
      <div class="target-group" data-target="{{ escapeXML $result.Target }}">
        <div class="target-header secret-header" onclick="this.parentElement.classList.toggle('collapsed')">
          <span class="target-toggle">▼</span>
          <span class="target-name">{{ escapeXML $result.Target }}</span>
          <span class="target-type">SECRET</span>
          {{- if $result.Class }}<span class="target-class">{{ $result.Class }}</span>{{- end }}
          <span class="target-counts">
            <span class="badge badge-SECRET">{{ len .Secrets }} secrets</span>
          </span>
        </div>
        <table>
          <thead>
            <tr>
              <th>Rule</th>
              <th>Category</th>
              <th>Severity</th>
              <th>Title</th>
              <th>Location</th>
            </tr>
          </thead>
          <tbody>
            {{- range .Secrets }}
            <tr data-severity="{{ .Severity }}" data-kind="secret" data-target="{{ escapeXML $result.Target }}">
              <td class="cve-id">{{ escapeXML .RuleID }}</td>
              <td class="version">{{ escapeXML (printf "%s" .Category) }}</td>
              <td><span class="badge badge-{{ .Severity }}">{{ .Severity }}</span></td>
              <td class="vuln-title">{{ escapeXML .Title }}</td>
              <td class="version">{{ escapeXML $result.Target }}:{{ .StartLine }}</td>
            </tr>
            {{- end }}
          </tbody>
        </table>
      </div>
    {{- end -}}
  {{- end -}}
  {{- if not $hasContent }}<div class="empty">No issues found</div>{{- end -}}
</div>

<script>
  const groups = Array.from(document.querySelectorAll('.target-group'));
  const targetSelect = document.getElementById('target-filter');
  const seenTargets = new Set();
  groups.forEach(g => {
    if (seenTargets.has(g.dataset.target)) return;
    seenTargets.add(g.dataset.target);
    const opt = document.createElement('option');
    opt.value = g.dataset.target;
    opt.textContent = g.dataset.target;
    targetSelect.appendChild(opt);
  });

  const rows       = Array.from(document.querySelectorAll('tr[data-severity]'));
  const vulnRows   = rows.filter(r => r.dataset.kind !== 'secret');
  const secretRows = rows.filter(r => r.dataset.kind === 'secret');

  // cartes de severite : CVE uniquement (les secrets ne polluent pas le compte)
  const counts = {};
  vulnRows.forEach(r => { const s = r.dataset.severity; counts[s] = (counts[s] || 0) + 1; });
  ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].forEach(s => {
    const el = document.getElementById('cnt-' + s);
    if (el) el.textContent = counts[s] || 0;
  });
  // carte KEV : nombre de CVE activement exploitees
  const kevEl = document.getElementById('cnt-KEV');
  if (kevEl) kevEl.textContent = vulnRows.filter(r => r.dataset.kev === 'true').length;
  // carte secrets : compte independant
  const secEl = document.getElementById('cnt-SECRET');
  if (secEl) secEl.textContent = secretRows.length;

  let currentSeverity = 'ALL';
  let currentTarget = 'ALL';
  let kevOnly = false;

  function applyFilters() {
    rows.forEach(r => {
      const sevMatch = currentSeverity === 'ALL' || r.dataset.severity === currentSeverity;
      const tgtMatch = currentTarget   === 'ALL' || r.dataset.target   === currentTarget;
      const kevMatch = !kevOnly || r.dataset.kev === 'true';
      r.classList.toggle('row-hidden', !(sevMatch && tgtMatch && kevMatch));
    });
    groups.forEach(g => {
      const visible = g.querySelectorAll('tr[data-severity]:not(.row-hidden)').length;
      g.classList.toggle('all-hidden', visible === 0);
    });
  }

  function setFilter(severity) {
    currentSeverity = severity;
    document.querySelectorAll('.filters button:not(#btn-KEV)').forEach(b => b.classList.remove('active'));
    document.getElementById('btn-' + severity).classList.add('active');
    applyFilters();
  }

  function setTargetFilter(target) {
    currentTarget = target;
    applyFilters();
  }

  function toggleKev() {
    kevOnly = !kevOnly;
    document.getElementById('btn-KEV').classList.toggle('active', kevOnly);
    applyFilters();
  }

  document.querySelectorAll('.links').forEach(cell => {
    const links = cell.querySelectorAll('a');
    if (links.length <= 3) return;
    links.forEach((l, i) => { if (i >= 3) l.style.display = 'none'; });
    const btn = document.createElement('button');
    btn.className = 'toggle-links';
    btn.textContent = '+ ' + (links.length - 3) + ' more';
    btn.onclick = function () {
      const collapsed = links[3].style.display === 'none';
      links.forEach((l, i) => { if (i >= 3) l.style.display = collapsed ? 'block' : 'none'; });
      btn.textContent = collapsed ? 'Show fewer' : '+ ' + (links.length - 3) + ' more';
    };
    cell.appendChild(btn);
  });

  document.getElementById('report-date').textContent =
    'Generated on ' + new Date().toLocaleString();
</script>

</body>
</html>
