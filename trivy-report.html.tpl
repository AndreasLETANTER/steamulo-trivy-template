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

    .filters { padding: .75rem 2rem; background: white; display: flex; gap: .5rem; border-bottom: 1px solid #e0e0e0; align-items: center; }
    .filters span { font-size: .85rem; color: #757575; margin-right: .25rem; }
    .filters button {
      padding: .35rem .9rem; border: 2px solid #e0e0e0; border-radius: 20px;
      cursor: pointer; font-size: .82rem; font-weight: 600; background: white; color: #424242;
      transition: all .15s;
    }
    .filters button:hover { border-color: #9fa8da; }
    .filters button.active { border-color: #1a237e; background: #e8eaf6; color: #1a237e; }

    .content { padding: 1.5rem 2rem; }
    table { width: 100%; border-collapse: collapse; background: white; border-radius: 8px; overflow: hidden; box-shadow: 0 1px 3px rgba(0,0,0,.1); }
    thead { background: #37474f; color: white; }
    th { padding: .7rem 1rem; text-align: left; font-size: .78rem; text-transform: uppercase; letter-spacing: .06em; white-space: nowrap; }
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

    .pkg-name { font-weight: 600; font-family: 'SFMono-Regular', Consolas, monospace; font-size: .82rem; white-space: nowrap; }
    .cve-id   { font-family: 'SFMono-Regular', Consolas, monospace; font-size: .82rem; white-space: nowrap; }
    .vuln-title { max-width: 260px; font-size: .84rem; color: #424242; }
    .version  { font-family: 'SFMono-Regular', Consolas, monospace; font-size: .82rem; white-space: nowrap; }

    .links a { display: block; font-size: .75rem; color: #1565c0; word-break: break-all; margin-bottom: .15rem; }
    .toggle-links {
      margin-top: .2rem; font-size: .75rem; color: #1565c0; cursor: pointer;
      background: none; border: none; padding: 0; text-decoration: underline;
    }
    .empty { text-align: center; padding: 3rem; color: #9e9e9e; font-size: .95rem; }
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
</div>

<div class="filters">
  <span>Filter:</span>
  <button class="active" id="btn-ALL"      onclick="setFilter('ALL')">All</button>
  <button              id="btn-CRITICAL" onclick="setFilter('CRITICAL')">Critical</button>
  <button              id="btn-HIGH"     onclick="setFilter('HIGH')">High</button>
  <button              id="btn-MEDIUM"   onclick="setFilter('MEDIUM')">Medium</button>
  <button              id="btn-LOW"      onclick="setFilter('LOW')">Low</button>
</div>

<div class="content">
  <table>
    <thead>
      <tr>
        <th>Package</th>
        <th>CVE / ID</th>
        <th>Title</th>
        <th>Severity</th>
        <th>Installed</th>
        <th>Fixed in</th>
        <th>References</th>
      </tr>
    </thead>
    <tbody id="vuln-table">
      {{- range . -}}
        {{- range .Vulnerabilities -}}
        <tr data-severity="{{.Severity}}">
          <td class="pkg-name">{{.PkgName}}</td>
          <td class="cve-id">{{.VulnerabilityID}}</td>
          <td class="vuln-title">{{.Title}}</td>
          <td><span class="badge badge-{{.Severity}}">{{.Severity}}</span></td>
          <td class="version">{{.InstalledVersion}}</td>
          <td class="version">{{.FixedVersion}}</td>
          <td class="links">
            {{- range .References -}}<a href="{{.}}" target="_blank" rel="noopener">{{.}}</a>{{- end -}}
          </td>
        </tr>
        {{- end -}}
      {{- end -}}
    </tbody>
  </table>
</div>

<script>
  // Summary counts
  const rows = Array.from(document.querySelectorAll('#vuln-table tr[data-severity]'));
  const counts = {};
  rows.forEach(r => { const s = r.dataset.severity; counts[s] = (counts[s] || 0) + 1; });
  ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].forEach(s => {
    const el = document.getElementById('cnt-' + s);
    if (el) el.textContent = counts[s] || 0;
  });

  // Filter
  function setFilter(severity) {
    document.querySelectorAll('.filters button').forEach(b => b.classList.remove('active'));
    document.getElementById('btn-' + severity).classList.add('active');
    rows.forEach(r => r.classList.toggle('row-hidden', severity !== 'ALL' && r.dataset.severity !== severity));
  }

  // Collapse links (show 3, toggle rest)
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

  // Empty state
  if (rows.length === 0) {
    document.getElementById('vuln-table').innerHTML =
      '<tr><td colspan="7" class="empty">No vulnerabilities found</td></tr>';
  }

  // Date
  document.getElementById('report-date').textContent =
    'Generated on ' + new Date().toLocaleString();
</script>

</body>
</html>
