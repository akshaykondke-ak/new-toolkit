# pentoolkit/utils/report.py
import json
import os
import glob
from datetime import datetime, timedelta
from pathlib import Path
import socket
from typing import Dict, List, Any, Optional
from jinja2 import Template

# Report directory
REPORT_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "reports")

def ensure_report_dir():
    """Ensure the reports directory exists."""
    os.makedirs(REPORT_DIR, exist_ok=True)

def generate_timestamp() -> str:
    """Generate a precise timestamp with milliseconds to avoid naming conflicts."""
    return datetime.utcnow().strftime("%Y%m%d_%H%M%S_%f")[:-3]

def sanitize_filename(name: str) -> str:
    """Make a filename safe by removing/replacing problematic characters."""
    # Replace problematic characters
    safe_chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-_"
    sanitized = "".join(c if c in safe_chars else "_" for c in name)
    # Remove consecutive underscores and limit length
    while "__" in sanitized:
        sanitized = sanitized.replace("__", "_")
    return sanitized[:100].strip("_")

def resolve_target_info(target: str) -> Dict[str, Any]:
    """Resolve target information including IP and hostname."""
    info = {"target": target, "ip": None, "hostname": None, "resolved": False}
    
    try:
        # Try to resolve hostname to IP
        ip = socket.gethostbyname(target)
        info["ip"] = ip
        info["resolved"] = True
        
        # If input was hostname, we have both
        if target != ip:
            info["hostname"] = target
        else:
            # Input was IP, try reverse lookup
            try:
                hostname = socket.gethostbyaddr(ip)[0]
                info["hostname"] = hostname
            except:
                info["hostname"] = ip
    except:
        # Resolution failed
        info["ip"] = target
        info["hostname"] = target
    
    return info

def save_report(data: dict, target: str, module: str):
    """Save report data as JSON with improved naming."""
    ensure_report_dir()
    
    safe_target = sanitize_filename(target)
    timestamp = generate_timestamp()
    
    filename = f"{safe_target}_{module}_{timestamp}.json"
    filepath = os.path.join(REPORT_DIR, filename)
    
    # Add metadata to the report
    enhanced_data = {
        "metadata": {
            "target": target,
            "target_info": resolve_target_info(target),
            "module": module,
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "filename": filename,
            "pentoolkit_version": "0.2.0"
        },
        "data": data
    }
    
    with open(filepath, 'w') as f:
        json.dump(enhanced_data, f, indent=2)
    
    print(f"[+] Report saved: {filepath}")
    return filepath

def save_raw(target: str, module: str, raw_data: str, extension: str = "txt"):
    """Save raw output data with improved naming."""
    ensure_report_dir()
    
    safe_target = sanitize_filename(target)
    timestamp = generate_timestamp()
    
    filename = f"{safe_target}_{module}_{timestamp}.{extension}"
    filepath = os.path.join(REPORT_DIR, filename)
    
    with open(filepath, 'w') as f:
        f.write(raw_data)
    
    print(f"[+] Raw output saved: {filepath}")
    return filepath

def save_report_html(data: dict, target: str, module: str):
    """Save individual module report as HTML."""
    ensure_report_dir()
    
    safe_target = sanitize_filename(target)
    timestamp = generate_timestamp()
    
    filename = f"{safe_target}_{module}_{timestamp}.html"
    filepath = os.path.join(REPORT_DIR, filename)
    
    html_content = generate_module_html(data, target, module)
    
    with open(filepath, 'w') as f:
        f.write(html_content)
    
    print(f"[+] HTML report saved: {filepath}")
    return filepath

def generate_module_html(data: dict, target: str, module: str) -> str:
    """Generate HTML for individual module report."""
    target_info = resolve_target_info(target)
    
    html_template = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Pentoolkit - {{ module|title }} Report - {{ target }}</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; background: white; border-radius: 8px; padding: 30px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        h1 { color: #2c3e50; border-bottom: 3px solid #3498db; padding-bottom: 10px; }
        h2 { color: #34495e; margin-top: 30px; }
        .meta-info { background: #ecf0f1; padding: 15px; border-radius: 5px; margin: 20px 0; }
        .meta-info strong { color: #2c3e50; }
        table { width: 100%; border-collapse: collapse; margin: 20px 0; }
        th, td { border: 1px solid #bdc3c7; padding: 12px; text-align: left; }
        th { background: #3498db; color: white; }
        tr:nth-child(even) { background: #f8f9fa; }
        .status-open { color: #27ae60; font-weight: bold; }
        .status-closed { color: #e74c3c; font-weight: bold; }
        .highlight { background: #fff3cd; padding: 10px; border-left: 4px solid #ffc107; margin: 10px 0; }
        pre { background: #2c3e50; color: #ecf0f1; padding: 15px; border-radius: 5px; overflow-x: auto; }
        .no-results { text-align: center; color: #7f8c8d; font-style: italic; padding: 40px; }
    </style>
</head>
<body>
    <div class="container">
        <h1>{{ module|title }} Report - {{ target }}</h1>
        
        <div class="meta-info">
            <strong>Target:</strong> {{ target }}<br>
            {% if target_info.ip and target_info.ip != target %}
            <strong>IP Address:</strong> {{ target_info.ip }}<br>
            {% endif %}
            {% if target_info.hostname and target_info.hostname != target %}
            <strong>Hostname:</strong> {{ target_info.hostname }}<br>
            {% endif %}
            <strong>Scan Time:</strong> {{ timestamp }}<br>
            <strong>Module:</strong> {{ module|title }}
        </div>

        {% if module == 'nmap' %}
            {% if data.open_ports %}
                <h2>Open Ports ({{ data.total_open_ports }})</h2>
                <table>
                    <thead>
                        <tr><th>Port</th><th>Protocol</th><th>Service</th><th>Product</th><th>Version</th><th>State</th></tr>
                    </thead>
                    <tbody>
                        {% for port in data.open_ports %}
                        <tr>
                            <td>{{ port.port }}</td>
                            <td>{{ port.protocol }}</td>
                            <td>{{ port.service }}</td>
                            <td>{{ port.product }} {{ port.version }}</td>
                            <td>{{ port.extrainfo }}</td>
                            <td class="status-open">{{ port.state }}</td>
                        </tr>
                        {% endfor %}
                    </tbody>
                </table>
                
                {% if data.service_summary %}
                <h2>Service Summary</h2>
                <ul>
                    {% for service, count in data.service_summary.items() %}
                    <li><strong>{{ service }}:</strong> {{ count }} port(s)</li>
                    {% endfor %}
                </ul>
                {% endif %}
                
                <div class="highlight">
                    <strong>Scan Arguments:</strong> {{ data.nmap_args }}
                </div>
            {% else %}
                <div class="no-results">No open ports found</div>
            {% endif %}
        {% elif module == 'ssl' %}
            {% if data.ssl_results %}
                {% for result in data.ssl_results %}
                <h2>SSL/TLS - Port {{ result.port }}</h2>
                <table>
                    <tr><th>Field</th><th>Value</th></tr>
                    <tr><td>SSL Version</td><td>{{ result.ssl_version }}</td></tr>
                    <tr><td>Cipher Suite</td><td>{{ result.cipher_suite }}</td></tr>
                    <tr><td>Valid From</td><td>{{ result.valid_from }}</td></tr>
                    <tr><td>Valid Until</td><td>{{ result.valid_until }}</td></tr>
                    <tr><td>Subject</td><td>{{ result.subject }}</td></tr>
                    <tr><td>Issuer</td><td>{{ result.issuer }}</td></tr>
                </table>
                {% endfor %}
            {% else %}
                <div class="no-results">No SSL/TLS services found</div>
            {% endif %}
        {% elif module == 'web_recon' %}
            {% if data.results %}
                <h2>Discovered Paths ({{ data.results|length }})</h2>
                <table>
                    <thead>
                        <tr><th>URL</th><th>Status</th><th>Length</th><th>Words</th></tr>
                    </thead>
                    <tbody>
                        {% for item in data.results %}
                        <tr>
                            <td>{{ item.url }}</td>
                            <td>{{ item.status }}</td>
                            <td>{{ item.length }}</td>
                            <td>{{ item.words }}</td>
                        </tr>
                        {% endfor %}
                    </tbody>
                </table>
            {% else %}
                <div class="no-results">No paths discovered</div>
            {% endif %}
        {% endif %}

        <h2>Technical Details</h2>
        <pre>{{ data | tojson(indent=2) }}</pre>
    </div>
</body>
</html>
    """
    
    template = Template(html_template)
    return template.render(
        data=data,
        target=target,
        target_info=target_info,
        module=module,
        timestamp=datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    )

def list_reports() -> List[str]:
    """List all available reports."""
    ensure_report_dir()
    pattern = os.path.join(REPORT_DIR, "*.json")
    reports = []
    for filepath in glob.glob(pattern):
        filename = os.path.basename(filepath)
        reports.append(filename)
    return sorted(reports)

def load_report(filename: str) -> Optional[Dict]:
    """Load a report by filename."""
    filepath = os.path.join(REPORT_DIR, filename)
    if not os.path.exists(filepath):
        print(f"[!] Report not found: {filename}")
        return None
    
    try:
        with open(filepath, 'r') as f:
            return json.load(f)
    except Exception as e:
        print(f"[!] Error loading report {filename}: {e}")
        return None

def find_target_reports(target: str) -> List[str]:
    """Find all reports for a specific target."""
    ensure_report_dir()
    safe_target = sanitize_filename(target)
    pattern = os.path.join(REPORT_DIR, f"{safe_target}_*_*.json")
    reports = []
    
    for filepath in glob.glob(pattern):
        filename = os.path.basename(filepath)
        reports.append(filename)
    
    # Also check for reports where original target matches
    all_reports = list_reports()
    for report_file in all_reports:
        report_data = load_report(report_file)
        if report_data and report_data.get("metadata", {}).get("target") == target:
            if report_file not in reports:
                reports.append(report_file)
    
    return sorted(reports)

def aggregate_target_reports(target: str) -> tuple[Dict, Optional[str]]:
    """Create an aggregated report for a target combining all modules."""
    target_reports = find_target_reports(target)
    
    if not target_reports:
        print(f"[!] No reports found for target: {target}")
        return {}, None
    
    # Load and organize reports by module
    modules_data = {}
    target_info = None
    raw_files = []
    
    for report_file in target_reports:
        report_data = load_report(report_file)
        if not report_data:
            continue
            
        metadata = report_data.get("metadata", {})
        module = metadata.get("module", "unknown")
        
        if not target_info:
            target_info = metadata.get("target_info", resolve_target_info(target))
        
        modules_data[module] = {
            "data": report_data.get("data", {}),
            "metadata": metadata,
            "report_file": report_file
        }
        
        # Look for associated raw files
        base_name = report_file.replace(".json", "")
        for ext in [".xml", ".txt", ".html"]:
            raw_file = base_name + ext
            raw_path = os.path.join(REPORT_DIR, raw_file)
            if os.path.exists(raw_path):
                raw_files.append(raw_file)
    
    # Generate aggregated report
    aggregated_data = {
        "target": target,
        "target_info": target_info,
        "generated": datetime.utcnow().isoformat() + "Z",
        "modules": modules_data,
        "raw_files": raw_files,
        "summary": generate_executive_summary(modules_data, target_info)
    }
    
    # Save aggregated HTML report
    html_path = save_aggregated_html_report(aggregated_data, target)
    
    return aggregated_data, html_path

def generate_executive_summary(modules_data: Dict, target_info: Dict) -> Dict:
    """Generate executive summary from all modules."""
    summary = {
        "total_open_ports": 0,
        "critical_services": [],
        "ssl_issues": [],
        "web_paths_found": 0,
        "security_score": 0,
        "recommendations": []
    }
    
    # Analyze nmap results
    if "nmap" in modules_data:
        nmap_data = modules_data["nmap"]["data"]
        summary["total_open_ports"] = len(nmap_data.get("open_ports", []))
        
        # Identify critical services
        critical_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 3389]
        for port_info in nmap_data.get("open_ports", []):
            if port_info["port"] in critical_ports:
                summary["critical_services"].append({
                    "port": port_info["port"],
                    "service": port_info["service"],
                    "version": f"{port_info.get('product', '')} {port_info.get('version', '')}".strip()
                })
    
    # Analyze SSL results
    if "ssl" in modules_data:
        ssl_data = modules_data["ssl"]["data"]
        if ssl_data.get("summary", {}).get("expiring_certificates"):
            summary["ssl_issues"].extend([
                f"Certificate on port {cert['port']} expires in {cert['days_left']} days"
                for cert in ssl_data["summary"]["expiring_certificates"]
            ])
    
    # Analyze web reconnaissance
    if "web_recon" in modules_data:
        web_data = modules_data["web_recon"]["data"]
        summary["web_paths_found"] = len(web_data.get("results", []))
    
    # Generate recommendations
    if summary["total_open_ports"] > 10:
        summary["recommendations"].append("Consider closing unnecessary open ports")
    
    if summary["ssl_issues"]:
        summary["recommendations"].append("Review and renew expiring SSL certificates")
    
    if not summary["recommendations"]:
        summary["recommendations"].append("Continue monitoring for security updates")
    
    # Simple security score (0-100)
    score = 100
    score -= min(summary["total_open_ports"] * 5, 50)  # Penalize open ports
    score -= len(summary["ssl_issues"]) * 10  # Penalize SSL issues
    summary["security_score"] = max(score, 0)
    
    return summary

def save_aggregated_html_report(data: Dict, target: str) -> str:
    """Save aggregated HTML report for a target."""
    ensure_report_dir()
    
    safe_target = sanitize_filename(target)
    timestamp = generate_timestamp()
    filename = f"{safe_target}_summary_{timestamp}.html"
    filepath = os.path.join(REPORT_DIR, filename)
    
    html_content = generate_aggregated_html(data)
    
    with open(filepath, 'w') as f:
        f.write(html_content)
    
    print(f"[+] Aggregated HTML report saved: {filepath}")
    return filepath

def generate_aggregated_html(data: Dict) -> str:
    """Generate comprehensive aggregated HTML report."""
    html_template = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Pentoolkit — Aggregated Report</title>
    <style>
        * { box-sizing: border-box; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; margin: 0; padding: 0; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); min-height: 100vh; }
        .container { max-width: 1400px; margin: 0 auto; padding: 20px; }
        .header { background: rgba(255,255,255,0.95); border-radius: 15px; padding: 30px; margin-bottom: 30px; box-shadow: 0 10px 30px rgba(0,0,0,0.2); }
        .header h1 { color: #2c3e50; margin: 0; font-size: 2.5rem; }
        .header .meta { color: #7f8c8d; margin-top: 10px; display: flex; gap: 30px; flex-wrap: wrap; }
        .summary-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 20px; margin-bottom: 30px; }
        .summary-card { background: rgba(255,255,255,0.95); border-radius: 15px; padding: 25px; box-shadow: 0 10px 30px rgba(0,0,0,0.1); }
        .summary-card h3 { margin: 0 0 15px 0; color: #2c3e50; display: flex; align-items: center; gap: 10px; }
        .summary-card .number { font-size: 2rem; font-weight: bold; color: #3498db; }
        .security-score { font-size: 3rem; font-weight: bold; }
        .score-excellent { color: #27ae60; }
        .score-good { color: #f39c12; }
        .score-poor { color: #e74c3c; }
        .module-section { background: rgba(255,255,255,0.95); border-radius: 15px; padding: 30px; margin-bottom: 30px; box-shadow: 0 10px 30px rgba(0,0,0,0.1); }
        .module-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 25px; }
        .module-title { color: #2c3e50; margin: 0; font-size: 1.8rem; }
        .module-badge { background: #3498db; color: white; padding: 5px 15px; border-radius: 20px; font-size: 0.9rem; }
        table { width: 100%; border-collapse: collapse; margin: 15px 0; }
        th, td { border: 1px solid #ddd; padding: 12px; text-align: left; }
        th { background: linear-gradient(135deg, #3498db, #2980b9); color: white; font-weight: 600; }
        tr:nth-child(even) { background: #f8f9fa; }
        tr:hover { background: #e3f2fd; }
        .status-open { color: #27ae60; font-weight: bold; }
        .status-warning { color: #f39c12; font-weight: bold; }
        .status-critical { color: #e74c3c; font-weight: bold; }
        .no-results { text-align: center; color: #95a5a6; font-style: italic; padding: 40px; font-size: 1.1rem; }
        .recommendations { background: #fff3cd; border: 1px solid #ffeaa7; border-radius: 10px; padding: 20px; margin: 20px 0; }
        .recommendations h4 { color: #856404; margin-top: 0; }
        .recommendations ul { margin: 10px 0; padding-left: 20px; }
        .raw-files { margin-top: 20px; }
        .raw-files a { display: inline-block; background: #6c757d; color: white; padding: 8px 16px; margin: 5px; text-decoration: none; border-radius: 5px; font-size: 0.9rem; }
        .raw-files a:hover { background: #545b62; }
        .collapsible { cursor: pointer; user-select: none; }
        .collapsible:after { content: ' ▼'; float: right; }
        .collapsible.active:after { content: ' ▲'; }
        .content { display: none; overflow: hidden; }
        .content.active { display: block; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Pentoolkit — Aggregated Report</h1>
            <div class="meta">
                <span><strong>Target:</strong> {{ data.target }}</span>
                {% if data.target_info.ip and data.target_info.ip != data.target %}
                <span><strong>IP:</strong> {{ data.target_info.ip }}</span>
                {% endif %}
                <span><strong>Generated:</strong> {{ data.generated }}</span>
                <span><strong>Reports:</strong> {{ data.modules|length }}</span>
            </div>
        </div>

        <!-- Executive Summary -->
        <div class="summary-grid">
            <div class="summary-card">
                <h3>🎯 Security Score</h3>
                <div class="security-score {% if data.summary.security_score >= 80 %}score-excellent{% elif data.summary.security_score >= 60 %}score-good{% else %}score-poor{% endif %}">
                    {{ data.summary.security_score }}/100
                </div>
            </div>
            <div class="summary-card">
                <h3>🔓 Open Ports</h3>
                <div class="number">{{ data.summary.total_open_ports }}</div>
            </div>
            <div class="summary-card">
                <h3>🌐 Web Paths</h3>
                <div class="number">{{ data.summary.web_paths_found }}</div>
            </div>
            <div class="summary-card">
                <h3>🔒 SSL Issues</h3>
                <div class="number">{{ data.summary.ssl_issues|length }}</div>
            </div>
        </div>

        {% if data.summary.recommendations %}
        <div class="recommendations">
            <h4>💡 Recommendations</h4>
            <ul>
                {% for rec in data.summary.recommendations %}
                <li>{{ rec }}</li>
                {% endfor %}
            </ul>
        </div>
        {% endif %}

        <!-- Raw Files -->
        {% if data.raw_files %}
        <div class="module-section">
            <h2>Raw Files</h2>
            <div class="raw-files">
                {% for file in data.raw_files %}
                <a href="{{ file }}" target="_blank">{{ file }}</a>
                {% endfor %}
            </div>
        </div>
        {% endif %}

        <!-- Module Results -->
        {% for module_name, module_data in data.modules.items() %}
        <div class="module-section">
            <div class="module-header">
                <h2 class="module-title collapsible">{{ module_name.upper() }}</h2>
                <span class="module-badge">Module</span>
            </div>
            
            <div class="content active">
                <p><strong>Report file:</strong> {{ module_data.report_file }}</p>
                
                {% if module_name == 'nmap' %}
                    {% set nmap_data = module_data.data %}
                    {% if nmap_data.open_ports %}
                        <h3>Open Ports ({{ nmap_data.total_open_ports }})</h3>
                        <table>
                            <thead>
                                <tr><th>Port</th><th>Protocol</th><th>Service</th><th>Product</th><th>Version</th><th>State</th></tr>
                            </thead>
                            <tbody>
                                {% for port in nmap_data.open_ports %}
                                <tr>
                                    <td><strong>{{ port.port }}</strong></td>
                                    <td>{{ port.protocol }}</td>
                                    <td>{{ port.service }}</td>
                                    <td>{{ port.product }}</td>
                                    <td>{{ port.version }}</td>
                                    <td class="status-open">{{ port.state }}</td>
                                </tr>
                                {% endfor %}
                            </tbody>
                        </table>
                        
                        {% if nmap_data.service_summary %}
                        <h4>Service Summary</h4>
                        <ul>
                            {% for service, count in nmap_data.service_summary.items() %}
                            <li><strong>{{ service }}:</strong> {{ count }} port(s)</li>
                            {% endfor %}
                        </ul>
                        {% endif %}
                    {% else %}
                        <div class="no-results">No open ports found</div>
                    {% endif %}
                {% elif module_name == 'ssl' %}
                    {% set ssl_data = module_data.data %}
                    {% if ssl_data.ssl_results %}
                        {% for result in ssl_data.ssl_results %}
                        <h3>SSL/TLS Analysis - Port {{ result.port }}</h3>
                        <table>
                            <tr><th>Field</th><th>Value</th></tr>
                            <tr><td>SSL Version</td><td>{{ result.ssl_version }}</td></tr>
                            <tr><td>Cipher Suite</td><td>{{ result.cipher_suite }}</td></tr>
                            <tr><td>Valid From</td><td>{{ result.valid_from }}</td></tr>
                            <tr><td>Valid Until</td><td>{{ result.valid_until }}</td></tr>
                            <tr><td>Certificate Chain Length</td><td>{{ result.cert_chain_length }}</td></tr>
                        </table>
                        {% endfor %}
                        
                        {% if ssl_data.get('security_summary', {}).get('expiring_certificates', []) %}
                        <h4 class="status-warning">⚠️ Expiring Certificates</h4>
                        <ul>
                            {% for cert in ssl_data.security_summary.expiring_certificates %}
                            <li>Port {{ cert.port }}: {{ cert.days_left }} days left</li>
                            {% endfor %}
                        </ul>
                        {% endif %}
                    {% else %}
                        <div class="no-results">No SSL/TLS services found</div>
                    {% endif %}
                {% elif module_name == 'web_recon' %}
                    {% set web_data = module_data.data %}
                    {% if web_data.results %}
                        <h3>Discovered Paths ({{ web_data.results|length }})</h3>
                        <table>
                            <thead>
                                <tr><th>URL</th><th>Status</th><th>Length</th><th>Words</th></tr>
                            </thead>
                            <tbody>
                                {% for item in web_data.results[:20] %}
                                <tr>
                                    <td>{{ item.url }}</td>
                                    <td class="{% if item.status|string|first == '2' %}status-open{% elif item.status|string|first == '4' %}status-warning{% else %}status-critical{% endif %}">{{ item.status }}</td>
                                    <td>{{ item.length }}</td>
                                    <td>{{ item.words }}</td>
                                </tr>
                                {% endfor %}
                            </tbody>
                        </table>
                        {% if web_data.results|length > 20 %}
                        <p><em>Showing top 20 results. See full report for complete list.</em></p>
                        {% endif %}
                    {% else %}
                        <div class="no-results">No web paths discovered</div>
                    {% endif %}
                {% else %}
                    <div class="no-results">Module results not yet implemented in aggregated view</div>
                {% endif %}
            </div>
        </div>
        {% endfor %}
    </div>

    <script>
        // Toggle collapsible sections
        document.querySelectorAll('.collapsible').forEach(item => {
            item.addEventListener('click', function() {
                this.classList.toggle('active');
                const content = this.parentElement.nextElementSibling;
                content.classList.toggle('active');
            });
        });
    </script>
</body>
</html>
    """
    
    template = Template(html_template)
    return template.render(data=data)

def cleanup_old_reports(days: int = 30):
    """Remove reports older than specified days."""
    ensure_report_dir()
    cutoff_date = datetime.now() - timedelta(days=days)
    removed_count = 0
    
    for filename in os.listdir(REPORT_DIR):
        filepath = os.path.join(REPORT_DIR, filename)
        if os.path.isfile(filepath):
            file_time = datetime.fromtimestamp(os.path.getmtime(filepath))
            if file_time < cutoff_date:
                try:
                    os.remove(filepath)
                    removed_count += 1
                    print(f"[+] Removed old report: {filename}")
                except Exception as e:
                    print(f"[!] Could not remove {filename}: {e}")
    
    print(f"[+] Cleanup complete. Removed {removed_count} old reports.")
    return removed_count

def export_report_to_text(report_data: Dict, output_file: str):
    """Export report data to plain text format."""
    with open(output_file, 'w') as f:
        f.write("=" * 60 + "\n")
        f.write("PENTOOLKIT SCAN REPORT\n")
        f.write("=" * 60 + "\n\n")
        
        metadata = report_data.get("metadata", {})
        f.write(f"Target: {metadata.get('target', 'Unknown')}\n")
        f.write(f"Module: {metadata.get('module', 'Unknown')}\n")
        f.write(f"Timestamp: {metadata.get('timestamp', 'Unknown')}\n")
        f.write(f"Pentoolkit Version: {metadata.get('pentoolkit_version', 'Unknown')}\n\n")
        
        data = report_data.get("data", {})
        f.write("SCAN RESULTS:\n")
        f.write("-" * 30 + "\n")
        f.write(json.dumps(data, indent=2))
    
    print(f"[+] Text report exported to: {output_file}")

def get_report_statistics():
    """Get statistics about all reports."""
    ensure_report_dir()
    reports = list_reports()
    
    stats = {
        "total_reports": len(reports),
        "modules": {},
        "targets": set(),
        "oldest_report": None,
        "newest_report": None,
        "total_size_mb": 0
    }
    
    for report_file in reports:
        # Get file stats
        filepath = os.path.join(REPORT_DIR, report_file)
        file_size = os.path.getsize(filepath)
        stats["total_size_mb"] += file_size / (1024 * 1024)
        
        file_time = datetime.fromtimestamp(os.path.getmtime(filepath))
        if not stats["oldest_report"] or file_time < stats["oldest_report"]:
            stats["oldest_report"] = file_time
        if not stats["newest_report"] or file_time > stats["newest_report"]:
            stats["newest_report"] = file_time
        
        # Parse report for additional stats
        report_data = load_report(report_file)
        if report_data:
            metadata = report_data.get("metadata", {})
            module = metadata.get("module", "unknown")
            target = metadata.get("target", "unknown")
            
            if module not in stats["modules"]:
                stats["modules"][module] = 0
            stats["modules"][module] += 1
            
            stats["targets"].add(target)
    
    stats["unique_targets"] = len(stats["targets"])
    stats["targets"] = list(stats["targets"])
    stats["total_size_mb"] = round(stats["total_size_mb"], 2)
    
    return stats

def search_reports(query: str, module: str = None) -> List[str]:
    """Search reports by target name or content."""
    ensure_report_dir()
    matching_reports = []
    
    reports = list_reports()
    if module:
        reports = [r for r in reports if f"_{module}_" in r]
    
    query_lower = query.lower()
    
    for report_file in reports:
        # Check filename match
        if query_lower in report_file.lower():
            matching_reports.append(report_file)
            continue
        
        # Check content match
        report_data = load_report(report_file)
        if report_data:
            metadata = report_data.get("metadata", {})
            target = metadata.get("target", "").lower()
            if query_lower in target:
                matching_reports.append(report_file)
    
    return sorted(matching_reports)

# Utility functions for backward compatibility
def get_reports_by_target(target: str) -> List[str]:
    """Get all reports for a target (alias for find_target_reports)."""
    return find_target_reports(target)

def create_summary_report(target: str) -> str:
    """Create summary report (alias for aggregate_target_reports)."""
    _, html_path = aggregate_target_reports(target)
    return html_path or ""