# pentoolkit/utils/report.py
from jinja2 import Template
import os
import json
from datetime import datetime
from typing import List

# Determine absolute project-reports folder reliably
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
REPORT_DIR = os.path.join(BASE_DIR, "reports")

# Ensure reports directory exists
os.makedirs(REPORT_DIR, exist_ok=True)


def _sanitize_target_for_fs(target: str) -> str:
    """
    Convert target/URL into a filesystem-safe canonical short name.
    Example: https://rivedix.com -> rivedix.com
    """
    t = (target or "").strip()
    if t.startswith("https://"):
        t = t[len("https://") :]
    elif t.startswith("http://"):
        t = t[len("http://") :]
    # replace path separators and colons with underscore
    t = t.replace("/", "_").replace(":", "_")
    return t


def save_report(data: dict, target: str, module: str):
    """
    Save scan results into a JSON file inside /reports
    Each target+module scan gets a timestamped entry.
    """
    timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    filename = f"{target}_{module}_{timestamp}.json"
    filepath = os.path.join(REPORT_DIR, filename)

    try:
        with open(filepath, "w") as f:
            json.dump(data, f, indent=4, default=str)
        print(f"[+] Report saved: {filepath}")
    except Exception as e:
        print(f"[!] Could not save report: {e}")


def list_reports() -> List[str]:
    """Return all report filenames"""
    try:
        return sorted(os.listdir(REPORT_DIR))
    except FileNotFoundError:
        return []


def load_report(filename: str):
    """Load a specific report by filename"""
    filepath = os.path.join(REPORT_DIR, filename)
    if not os.path.exists(filepath):
        return None
    try:
        with open(filepath, "r") as f:
            return json.load(f)
    except Exception as e:
        print(f"[!] Failed to load {filename}: {e}")
        return None


def save_raw(target: str, module: str, raw_text: str, ext: str = "xml"):
    """
    Save raw output (e.g., nmap XML) to reports directory.
    """
    timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    filename = f"{target}_{module}_{timestamp}.{ext}"
    filepath = os.path.join(REPORT_DIR, filename)
    try:
        with open(filepath, "w") as f:
            f.write(raw_text)
        print(f"[+] Raw output saved: {filepath}")
    except Exception as e:
        print(f"[!] Could not save raw output: {e}")


def _report_files_for_target(target: str):
    """
    Return list of filenames in REPORT_DIR that match the provided target.
    Matches either the raw target string or the sanitized variant.
    """
    sanitized = _sanitize_target_for_fs(target)
    prefixes = {f"{target}_", f"{sanitized}_"}
    files = []
    for f in sorted(os.listdir(REPORT_DIR)):
        for p in prefixes:
            if f.startswith(p):
                files.append(f)
                break
    return files


def aggregate_target_reports(target: str):
    """
    Merge all per-module reports for `target_*` into a single summary JSON + HTML.
    Returns the summary dict and the HTML filepath (or (None, None) on error).
    """
    files = _report_files_for_target(target)
    if not files:
        print(f"[!] No reports found for target: {target}")
        return None, None

    merged = {"target": target, "generated": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"), "modules": {}}
    # Track any raw files (xml, txt) to include as links
    raw_files = []

    for fname in files:
        filepath = os.path.join(REPORT_DIR, fname)
        # Consider JSON module reports
        if fname.endswith(".json"):
            data = load_report(fname)
            if data is None:
                continue
            # Expect name pattern: <target>_<module>_<timestamp>.json
            parts = fname.split("_")
            module = parts[1] if len(parts) > 2 else "unknown"
            merged["modules"].setdefault(module, []).append({
                "filename": fname,
                "data": data
            })
        else:
            # collect other raw files (e.g., .xml, .txt)
            raw_files.append(fname)

    # Save merged JSON summary
    summary_obj = merged
    save_report(summary_obj, _sanitize_target_for_fs(target), "summary")

    # Render a nicer summary HTML (collapsible modules, whois improvements)
    timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    html_filename = f"{_sanitize_target_for_fs(target)}_summary_{timestamp}.html"
    html_path = os.path.join(REPORT_DIR, html_filename)

    html_template = """
    <!doctype html>
    <html>
    <head>
      <meta charset="utf-8"/>
      <title>Pentoolkit Summary - {{ target }}</title>
      <meta name="viewport" content="width=device-width,initial-scale=1" />
      <style>
        :root{
          --bg:#f7fafc; --card:#ffffff; --muted:#6b7280; --brand:#2563eb;
          --accent:#111827; --success:#059669;
        }
        body{font-family:Inter, system-ui, -apple-system, "Segoe UI", Roboto, "Helvetica Neue", Arial; background:var(--bg); margin:0; padding:24px; color:var(--accent)}
        .container{max-width:1100px;margin:0 auto}
        header{display:flex;align-items:center;justify-content:space-between;margin-bottom:18px}
        h1{margin:0;font-size:1.4rem}
        .meta{color:var(--muted)}
        .modules{display:flex;flex-direction:column;gap:12px}
        .card{background:var(--card);border-radius:10px;box-shadow:0 4px 14px rgba(16,24,40,0.06);padding:14px;border:1px solid #e6eef8}
        .card h2{margin:0;font-size:1.05rem;display:flex;justify-content:space-between;align-items:center}
        .badge{background:#eef2ff;color:#1e3a8a;padding:4px 8px;border-radius:6px;font-size:0.85rem}
        .meta-row{display:flex;gap:12px;align-items:center;color:var(--muted);margin-top:6px}
        table{border-collapse:collapse;width:100%;margin-top:8px}
        th,td{padding:8px;border:1px solid #eef2f6;text-align:left;font-size:0.95rem}
        th{background:#fbfdff}
        .small{font-size:0.9rem;color:var(--muted)}
        .toggle{cursor:pointer; user-select:none}
        .collapsible{max-height:0;overflow:hidden;transition:max-height .28s ease}
        .collapsible.open{max-height:2000px;transition:max-height .45s cubic-bezier(.2,.9,.2,1)}
        .whois-grid{display:grid;grid-template-columns:1fr 1fr;gap:10px}
        pre.raw{background:#0f1724;color:#e6eef8;padding:12px;border-radius:8px;overflow:auto;max-height:320px}
        .right{display:flex;gap:8px;align-items:center}
        .muted-pill{background:#f1f5f9;color:#475569;padding:6px 8px;border-radius:999px;font-size:0.85rem}
        .link{color:var(--brand);text-decoration:none}
        @media (max-width:700px){ .whois-grid{grid-template-columns:1fr} }
      </style>
    </head>
    <body>
      <div class="container">
        <header>
          <div>
            <h1>Pentoolkit — Aggregated Report</h1>
            <div class="meta small">Target: <strong>{{ target }}</strong> &nbsp;•&nbsp; Generated: {{ generated }}</div>
          </div>
          <div class="right small"><span class="muted-pill">Reports: {{ modules|length }}</span></div>
        </header>

        {% if raw_files %}
        <div class="card">
          <strong>Raw files</strong>
          <div class="small" style="margin-top:6px;">
            {% for rf in raw_files %}
              <div><a class="link" href="{{ rf }}">{{ rf }}</a></div>
            {% endfor %}
          </div>
        </div>
        {% endif %}

        <div class="modules">
          {% for module, runs in modules.items() %}
          <div class="card">
            <h2>
              <span>{{ module|upper() }} <span class="small">({{ runs|length }} run(s))</span></span>
              <span class="right">
                <span class="badge">Module</span>
                <span style="width:12px"></span>
                <span class="toggle" data-target="mod-{{ loop.index0 }}">▾</span>
              </span>
            </h2>

            <div id="mod-{{ loop.index0 }}" class="collapsible">
              {% for run in runs %}
                <div style="margin-top:12px">
                  <div class="small">Report file: <code>{{ run.filename }}</code></div>

                  {% set data = run.data %}

                  {# WHOIS: display as compact card if present #}
                  {% if module == 'whois' %}
                    <div style="margin-top:8px" class="whois-grid">
                      <div>
                        <table>
                          <tr><th>Domain</th><td>{{ data.whois.domain_name | default(target) }}</td></tr>
                          <tr><th>Registrar</th><td>{{ data.whois.registrar | default('-') }}</td></tr>
                          <tr><th>Created</th><td>{{ data.whois.creation_date | default('-') }}</td></tr>
                          <tr><th>Expires</th><td>{{ data.whois.expiration_date | default('-') }}</td></tr>
                        </table>
                      </div>
                      <div>
                        <table>
                          <tr><th>Name servers</th><td>{{ data.whois.name_servers | default('-') }}</td></tr>
                          <tr><th>Emails</th><td>{{ data.whois.emails | default('-') }}</td></tr>
                          <tr><th>Status</th><td>{{ data.whois.status | default('-') }}</td></tr>
                          <tr><th>Raw saved</th><td>{% if data.whois.raw_text %}Yes{% else %}No{% endif %}</td></tr>
                        </table>
                      </div>
                    </div>

                    {% if data.whois.raw_text %}
                      <div style="margin-top:10px">
                        <button class="toggle-raw" data-target="raw-{{ loop.index0 }}">Show / Hide Raw WHOIS</button>
                        <div id="raw-{{ loop.index0 }}" class="collapsible" style="margin-top:8px">
                          <pre class="raw">{{ data.whois.raw_text[:200000] }}</pre>
                        </div>
                      </div>
                    {% endif %}
                  {% endif %}

                  {# NMAP: show open_ports if present #}
                  {% if data.get('open_ports') %}
                    <div style="margin-top:8px">
                      <h4 class="small">Open Ports</h4>
                      <table>
                        <tr><th>Port</th><th>Proto</th><th>Service</th><th>Product</th><th>Version</th><th>State</th></tr>
                        {% for p in data.get('open_ports') %}
                          <tr>
                            <td>{{ p['port'] }}</td>
                            <td>{{ p['protocol'] }}</td>
                            <td>{{ p['service'] }}</td>
                            <td>{{ p['product'] }}</td>
                            <td>{{ p['version'] }}</td>
                            <td>{{ p['state'] }}</td>
                          </tr>
                        {% endfor %}
                      </table>
                    </div>
                  {% endif %}

                  {# SSL: show cert summary if present #}
                  {% if data.get('ssl_version') or data.get('valid_until') %}
                    <div style="margin-top:8px">
                      <h4 class="small">SSL Summary</h4>
                      <table>
                        <tr><th>Field</th><th>Value</th></tr>
                        <tr><td>SSL Version</td><td>{{ data.get('ssl_version') }}</td></tr>
                        <tr><td>Subject</td><td>{{ data.get('subject') }}</td></tr>
                        <tr><td>Issuer</td><td>{{ data.get('issuer') }}</td></tr>
                        <tr><td>Valid Until</td><td>{{ data.get('valid_until') }}</td></tr>
                      </table>
                    </div>
                  {% endif %}

                  {# WEB_RECON: show ffuf results if present #}
                  {% if module == 'web_recon' and data.get('results') %}
                    <div style="margin-top:8px">
                      <h4 class="small">Web Recon Results (ffuf)</h4>
                      <table>
                        <tr><th>URL</th><th>Status</th><th>Length</th><th>Words</th><th>Lines</th></tr>
                        {% for r in data.get('results') %}
                          <tr>
                            <td>{{ r.get('url') }}</td>
                            <td>{{ r.get('status') }}</td>
                            <td>{{ r.get('length') }}</td>
                            <td>{{ r.get('words') }}</td>
                            <td>{{ r.get('lines') }}</td>
                          </tr>
                        {% endfor %}
                      </table>
                    </div>
                  {% endif %}

                  {# Generic dump for other modules #}
                  {% if (not data.get('open_ports')) and (not data.get('ssl_version')) and (module != 'whois') and (module != 'web_recon') %}
                    <div class="small" style="margin-top:8px">Keys: {{ data.keys()|list }}</div>
                  {% endif %}

                </div>
                <hr/>
              {% endfor %}
            </div>
          </div>
          {% endfor %}
        </div>

      </div>

      <script>
        // toggles for module cards
        document.querySelectorAll('.toggle').forEach(function(t){
          t.addEventListener('click', function(){
            const id = t.getAttribute('data-target');
            const el = document.getElementById(id);
            if(!el) return;
            const open = el.classList.toggle('open');
            t.textContent = open ? '▾' : '▸';
            // ensure that when opening we set a big max-height (handled by CSS)
          });
        });

        // toggles for raw blocks
        document.querySelectorAll('.toggle-raw').forEach(function(b){
          b.addEventListener('click', function(){
            const id = b.getAttribute('data-target');
            const el = document.getElementById(id);
            if(!el) return;
            el.classList.toggle('open');
          });
        });

        // Open the first module by default
        const first = document.querySelector('.collapsible');
        if(first) first.classList.add('open');
      </script>
    </body>
    </html>
    """

    try:
        template = Template(html_template)
        rendered = template.render(
            target=target,
            generated=summary_obj["generated"],
            modules=summary_obj["modules"],
            raw_files=raw_files
        )
        with open(html_path, "w") as fh:
            fh.write(rendered)
        print(f"[+] Summary HTML saved: {html_path}")
    except Exception as e:
        print(f"[!] Could not save aggregated HTML report: {e}")
        return summary_obj, None

    return summary_obj, html_path


def save_report_html(data: dict, target: str, module: str):
    """
    Save scan results into an HTML report using Jinja2 template
    Improves on the previous template: compact header + service distribution chart fallback.
    """
    timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    filename = f"{target}_{module}_{timestamp}.html"
    filepath = os.path.join(REPORT_DIR, filename)

    # Simple but neat HTML template (safe access using get)
    html_template = """
    <!doctype html>
    <html>
    <head>
        <meta charset="utf-8"/>
        <title>Pentoolkit Report - {{ target }} ({{ module }})</title>
        <meta name="viewport" content="width=device-width,initial-scale=1" />
        <style>
            body { font-family: Inter, system-ui, -apple-system, "Segoe UI", Roboto; margin: 18px; color: #111827; background:#f8fafc;}
            .card{background:#fff;border-radius:10px;padding:16px;box-shadow:0 6px 18px rgba(17,24,39,0.06);max-width:1100px;margin:0 auto}
            h1{margin:0 0 6px 0}
            .meta{color:#6b7280;margin-bottom:12px}
            table{border-collapse:collapse;width:100%;margin-top:12px}
            th, td{border:1px solid #e6eef8;padding:8px;text-align:left}
            th{background:#f8fafc}
            .small{font-size:0.9rem;color:#6b7280}
            pre.raw{background:#0f1724;color:#e6eef8;padding:12px;border-radius:8px;overflow:auto;max-height:360px}
        </style>
    </head>
    <body>
        <div class="card">
            <h1>Pentoolkit Report</h1>
            <div class="meta">Target: <strong>{{ target }}</strong> &nbsp; • &nbsp; Module: <strong>{{ module }}</strong> &nbsp; • &nbsp; Generated: {{ timestamp }}</div>

            {% if data.get('service_summary') %}
            <h2>Service Summary</h2>
            <table>
                <tr><th>Service</th><th>Count</th></tr>
                {% for svc, cnt in data.get('service_summary').items() %}
                <tr><td>{{ svc }}</td><td>{{ cnt }}</td></tr>
                {% endfor %}
            </table>
            {% endif %}

            {% if data.get('open_ports') %}
            <h2 style="margin-top:14px">Open Ports</h2>
            <table>
                <tr><th>Port</th><th>Protocol</th><th>Service</th><th>Product</th><th>Version</th><th>State</th></tr>
                {% for p in data.get('open_ports') %}
                <tr>
                    <td>{{ p['port'] }}</td>
                    <td>{{ p['protocol'] }}</td>
                    <td>{{ p['service'] }}</td>
                    <td>{{ p['product'] }}</td>
                    <td>{{ p['version'] }}</td>
                    <td>{{ p['state'] }}</td>
                </tr>
                {% endfor %}
            </table>
            {% else %}
            <p class="small">No open ports found.</p>
            {% endif %}

            {% if data.get('raw_text') %}
            <h3 style="margin-top:12px">Raw Output</h3>
            <pre class="raw">{{ data.get('raw_text')[:200000] }}</pre>
            {% endif %}
        </div>
    </body>
    </html>
    """
    try:
        template = Template(html_template)
        rendered = template.render(
            target=target,
            module=module,
            timestamp=timestamp,
            data=data
        )
        with open(filepath, "w") as f:
            f.write(rendered)
        print(f"[+] HTML report saved: {filepath}")
    except Exception as e:
        print(f"[!] Could not save HTML report: {e}")
