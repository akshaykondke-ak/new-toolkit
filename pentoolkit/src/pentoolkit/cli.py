# pentoolkit/cli.py
import typer
import os
import yaml
from pentoolkit import main
from pentoolkit.utils import report
from pentoolkit.utils.config import get_config, reload_config, DEFAULT_CONFIG_PATH
from pathlib import Path
import http.server
import socketserver
import webbrowser

app = typer.Typer(help="Pentoolkit CLI")

# Sub-apps
scan_app = typer.Typer(help="Run scans")
report_app = typer.Typer(help="View reports")
config_app = typer.Typer(help="Configuration management")

# Attach sub-apps
app.add_typer(scan_app, name="scan")
app.add_typer(report_app, name="report")
app.add_typer(config_app, name="config")

# ==================== SCAN COMMANDS ====================

@scan_app.command("run")
def run_scan(
    target: str = typer.Argument(..., help="Target hostname or URL"),
    modules: str = typer.Option("all", help="Modules to run (comma-separated or 'all')"),
    scan_type: str = typer.Option("default", help="nmap scan type: default,syn,udp,aggressive"),
    nmap_args: str = typer.Option("", help="Custom Nmap arguments")
):
    """Run scans on a target."""
    typer.echo(f"[+] Running scans on: {target} (modules={modules})")
    results = main.run_scan(target, modules, scan_type=scan_type, extra_args=nmap_args)
    typer.echo("[+] Scan finished.")

    if results:
        for module, result in results.items():
            if result:
                typer.echo(f"[+] {module.upper()} module: results saved to reports/")
            else:
                typer.echo(f"[!] {module.upper()} module: no results")

@scan_app.command("web-recon")
def run_web_recon(
    target: str = typer.Argument(..., help="Target URL"),
    wordlist: str = typer.Option(None, help="Wordlist path"),
    extensions: str = typer.Option(None, help="File extensions to fuzz"),
    threads: int = typer.Option(None, help="Number of threads"),
    timeout: int = typer.Option(None, help="Request timeout in seconds")
):
    """Run Web Recon (ffuf) on a target."""
    from pentoolkit.modules import web_recon
    web_recon.run_ffuf(target, wordlist=wordlist, extensions=extensions, threads=threads, timeout=timeout)

# ==================== REPORT COMMANDS ====================

@report_app.command("list")
def list_reports():
    """List all saved reports"""
    reports_list = report.list_reports()
    if not reports_list:
        typer.echo("[!] No reports found.")
    else:
        typer.echo("Available reports:")
        for r in reports_list:
            typer.echo(f"  - {r}")

@report_app.command("show")
def show_report(filename: str):
    """Show a saved report by filename"""
    data = report.load_report(filename)
    if not data:
        typer.echo(f"[!] Could not read {filename}")
    else:
        typer.echo(f"[+] Loaded {filename}. Use 'pentoolkit report serve' to view HTML reports.")

@report_app.command("summary")
def report_summary(target: str):
    """Generate an aggregated HTML report for a target."""
    typer.echo(f"[+] Building aggregated report for: {target}")
    summary_obj, html_path = report.aggregate_target_reports(target)
    if html_path:
        typer.echo(f"[+] Aggregated report created: {html_path}")
    else:
        typer.echo("[!] No reports found for aggregation.")

@report_app.command("serve")
def serve_reports(port: int = 8080, open_browser: bool = True):
    """Serve the reports directory over HTTP."""
    report_dir = getattr(report, "REPORT_DIR", os.path.join(os.path.dirname(__file__), "..", "reports"))
    report_dir = os.path.abspath(report_dir)

    if not os.path.isdir(report_dir):
        typer.echo(f"[!] Reports directory not found: {report_dir}")
        raise typer.Exit(code=1)

    typer.echo(f"[+] Serving reports at http://localhost:{port}/")
    os.chdir(report_dir)

    Handler = http.server.SimpleHTTPRequestHandler
    with socketserver.TCPServer(("", port), Handler) as httpd:
        if open_browser:
            try:
                webbrowser.open(f"http://localhost:{port}/")
            except Exception:
                pass
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            typer.echo("[+] Server stopped.")

# ==================== CONFIG COMMANDS ====================

@config_app.command("show")
def show_config(section: str = typer.Option(None, help="Section name (e.g., nmap, ssl)")):
    """Show current configuration."""
    config = get_config()
    if section:
        section_data = config.get_section(section)
        if section_data:
            typer.echo(yaml.dump({section: section_data}, default_flow_style=False))
        else:
            typer.echo(f"[!] Section '{section}' not found")
    else:
        typer.echo(f"Config path: {config.config_path}")
        if config.config_path.exists():
            typer.echo("✓ Config file exists")
        else:
            typer.echo("✗ Config file not found (using defaults)")

@config_app.command("path")
def show_config_path():
    """Show config file path"""
    config = get_config()
    typer.echo(f"Config path: {config.config_path}")

@config_app.command("reload")
def reload_configuration():
    """Reload config from file"""
    try:
        reload_config()
        typer.echo("[+] Config reloaded successfully")
    except Exception as e:
        typer.echo(f"[!] Failed: {e}")

@config_app.command("validate")
def validate_config():
    """Validate configuration settings"""
    config = get_config()
    typer.echo("[+] Config validation placeholder (extend checks here)")

@config_app.command("create")
def create_config():
    """Create a default config file"""
    config_content = '''# Pentoolkit Default Config
nmap:
  default_args: "-sV"
ssl:
  default_port: 443
web_recon:
  wordlists:
    - "/usr/share/wordlists/dirb/common.txt"
'''
    config_path = Path("./config.yaml")
    with open(config_path, "w") as f:
        f.write(config_content)
    typer.echo(f"[+] Default config created at {config_path}")

@config_app.command("test-wordlist")
def test_wordlist():
    """Check if wordlists exist"""
    config = get_config()
    for wl in config.web_recon_config.wordlists:
        expanded = os.path.expanduser(wl)
        if os.path.exists(expanded):
            typer.echo(f"✓ {wl}")
        else:
            typer.echo(f"✗ {wl} (not found)")

if __name__ == "__main__":
    app()
