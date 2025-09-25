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
import os

app = typer.Typer(help="Pentoolkit CLI")

scan_app = typer.Typer(help="Run scans")
report_app = typer.Typer(help="View reports")
config_app = typer.Typer(help="Configuration management")  # ← NEW

app.add_typer(scan_app, name="scan")
app.add_typer(report_app, name="report")
app.add_typer(config_app, name="config")  # ← NEW

# Add this after report_app
config_app = typer.Typer(help="Configuration management")
app.add_typer(config_app, name="config")


@scan_app.command("run")
def run_scan(
    target: str = typer.Argument(..., help="Target hostname or URL (e.g., example.com or https://example.com)"),
    modules: str = typer.Option(
        "all",
        help="Modules to run (comma-separated or 'all'). Options: nmap, ssl, whois, waf, web_recon"
    ),
    scan_type: str = typer.Option("default", help="nmap scan type: default,syn,udp,aggressive"),
    nmap_args: str = typer.Option("", help="Custom Nmap arguments (advanced)")
):
    """
    Run scans on a target.

    Example:
      pentoolkit scan run scanme.nmap.org --modules nmap,ssl
      pentoolkit scan run https://rivedix.com --modules nmap,web_recon --nmap-args "-sC -O"
    """
    typer.echo(f"[+] Running scans on: {target} (modules={modules})")
    results = main.run_scan(target, modules, scan_type=scan_type, extra_args=nmap_args)
    typer.echo("[+] Scan finished.")

    # Show short summary (not full JSON)
    if results:
        for module, result in results.items():
            if result:
                typer.echo(f"[+] {module.upper()} module: results saved to reports/")
            else:
                typer.echo(f"[!] {module.upper()} module: no results")


# Optional dedicated subcommand for web-recon with more control
@scan_app.command("web-recon")
def run_web_recon(
    target: str = typer.Argument(..., help="Target URL (e.g., https://example.com)"),
    wordlist: str = typer.Option(None, help="Wordlist path for ffuf (uses config default if not specified)"),
    extensions: str = typer.Option(None, help="File extensions to fuzz (comma-separated, e.g., php,html)"),
    threads: int = typer.Option(None, help="Number of threads (uses config default if not specified)"),
    timeout: int = typer.Option(None, help="Request timeout in seconds (uses config default if not specified)")
):
    """Run Web Recon (ffuf) on a target."""
    from pentoolkit.modules import web_recon
    web_recon.run_ffuf(target, wordlist=wordlist, extensions=extensions, threads=threads, timeout=timeout)


@report_app.command("list")
def list_reports():
    """List all saved reports"""
    reports = report.list_reports()
    if not reports:
        typer.echo("[!] No reports found.")
    else:
        typer.echo("Available reports:")
        for r in reports:
            typer.echo(f"  - {r}")


@report_app.command("show")
def show_report(filename: str):
    """Show a saved report by filename"""
    data = report.load_report(filename)
    if not data:
        typer.echo(f"[!] Could not read {filename}")
        return
    typer.echo(f"[+] Loaded {filename}. Use 'pentoolkit report serve' to view HTML reports in browser.")


@report_app.command("summary")
def report_summary(target: str = typer.Argument(..., help="Target hostname or IP")):
    """
    Generate a single aggregated HTML report for a target by combining per-module reports.
    Example: pentoolkit report summary 172.16.1.47
    """
    typer.echo(f"[+] Building aggregated report for: {target}")
    summary_obj, html_path = report.aggregate_target_reports(target)
    if html_path:
        typer.echo(f"[+] Aggregated report created: {html_path}")
    else:
        typer.echo("[!] Aggregation failed or no reports found.")


@report_app.command("serve")
def serve_reports(port: int = typer.Option(8080, help="Port to serve reports on (default: 8080)"),
                  open_browser: bool = typer.Option(True, help="Open the reports page in default browser")):
    """
    Serve the reports/ directory over HTTP so you can browse HTML reports.
    Example: pentoolkit report serve --port 8080
    """
    report_dir = report.REPORT_DIR if hasattr(report, "REPORT_DIR") else os.path.join(os.path.abspath(os.path.dirname(__file__)), "..", "reports")
    report_dir = os.path.abspath(report_dir)

    if not os.path.isdir(report_dir):
        typer.echo(f"[!] Reports directory does not exist: {report_dir}")
        raise typer.Exit(code=1)

    typer.echo(f"[+] Serving reports from: {report_dir} at http://localhost:{port}/")
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
            typer.echo("[+] Stopped serving reports.")


# ==================== CONFIG COMMANDS (NEW) ====================

@config_app.command("show")
def show_config(
    section: str = typer.Option(None, help="Show specific section (e.g., 'nmap', 'ssl', 'web_recon')")
):
    """Show current configuration."""
    config = get_config()
    
    if section:
        # Show specific section
        section_data = config.get_section(section)
        if section_data:
            typer.echo(f"[{section}] Configuration:")
            typer.echo(yaml.dump({section: section_data}, default_flow_style=False))
        else:
            typer.echo(f"[!] Section '{section}' not found in configuration")
            return
    else:
        # Show all configuration overview
        typer.echo(f"Configuration loaded from: {config.config_path}")
        if config.config_path.exists():
            typer.echo("✓ Config file exists")
        else:
            typer.echo("✗ Config file not found (using defaults)")
            
        typer.echo("\nAvailable sections:")
        if config._config_data:
            for section_name in config._config_data.keys():
                typer.echo(f"  - {section_name}")
        else:
            typer.echo("  (using default configuration)")
        
        typer.echo("\nTo view a specific section:")
        typer.echo("  pentoolkit config show --section nmap")
        typer.echo("  pentoolkit config show --section web_recon")


@config_app.command("path")
def show_config_path():
    """Show the path to the configuration file."""
    config = get_config()
    typer.echo(f"Config file path: {config.config_path}")
    if config.config_path.exists():
        typer.echo("✓ Config file exists")
        # Show file size
        size = config.config_path.stat().st_size
        typer.echo(f"  Size: {size} bytes")
    else:
        typer.echo("✗ Config file not found (using defaults)")
        typer.echo("  Run 'pentoolkit config create' to create a default config file")


@config_app.command("reload")
def reload_configuration():
    """Reload configuration from file."""
    try:
        reload_config()
        typer.echo("[+] Configuration reloaded successfully")
    except Exception as e:
        typer.echo(f"[!] Failed to reload configuration: {e}")


@config_app.command("validate")
def validate_config():
    """Validate current configuration."""
    config = get_config()
    issues = []
    
    typer.echo("Validating configuration...")
    
    # Check wordlists
    web_config = config.web_recon_config
    found_wordlist = config.find_wordlist(web_config.wordlists)
    if not found_wordlist:
        issues.append("No valid wordlists found for web reconnaissance")
    else:
        typer.echo(f"✓ Wordlist found: {found_wordlist}")
    
    # Check timeouts
    global_config = config.global_config
    if global_config.default_timeout < 5:
        issues.append("Default timeout is very low (< 5 seconds)")
    else:
        typer.echo(f"✓ Default timeout: {global_config.default_timeout}s")
    
    # Check network configuration
    network_config = config.network_config
    if network_config.proxy["enabled"]:
        if not network_config.proxy["http_proxy"]:
            issues.append("Proxy enabled but no HTTP proxy configured")
        else:
            typer.echo(f"✓ Proxy configured: {network_config.proxy['http_proxy']}")
    else:
        typer.echo("ℹ Proxy not configured")
    
    # Check security settings
    security_config = config.security_config
    if not security_config.allowed_networks:
        typer.echo("⚠️  No network restrictions configured (all networks allowed)")
    else:
        typer.echo(f"✓ Network restrictions: {len(security_config.allowed_networks)} allowed ranges")
    
    # Check SSL settings
    ssl_config = config.ssl_config
    typer.echo(f"✓ SSL default port: {ssl_config.default_port}")
    typer.echo(f"✓ SSL additional ports: {ssl_config.additional_ports}")
    
    # Check nmap settings
    nmap_config = config.nmap_config
    typer.echo(f"✓ Nmap scan types: {len(nmap_config.scan_types)} configured")
    
    # Report results
    if issues:
        typer.echo(f"\n[!] Found {len(issues)} configuration issues:")
        for issue in issues:
            typer.echo(f"  - {issue}")
    else:
        typer.echo("\n[+] Configuration validation passed!")


@config_app.command("create")
def create_default_config():
    """Create a default configuration file."""
    if DEFAULT_CONFIG_PATH.exists():
        overwrite = typer.confirm(f"Config file already exists at {DEFAULT_CONFIG_PATH}. Overwrite?")
        if not overwrite:
            typer.echo("Cancelled.")
            return
    
    # Create default config content
    default_config_content = '''# Pentoolkit Configuration File
# This file contains default settings for all modules

# Global Settings
global:
  default_timeout: 30
  default_threads: 40
  output:
    colored_output: true
    log_level: INFO
    save_raw_output: true
    report_formats: both

# Nmap Scanner Settings
nmap:
  default_args: "-sV"
  scan_types:
    default: "-sV"
    syn: "-sS -sV"
    udp: "-sU -sV --top-ports 1000"
    aggressive: "-A -sV -O"
    stealth: "-sS -sV -f -T2"
    discovery: "-sn"
  timeout: 300
  host_timeout: 30
  skip_ping: false
  default_nse_scripts: ""
  nse_script_dir: ""

# SSL Scanner Settings  
ssl:
  default_port: 443
  additional_ports: [8443, 8080, 9443]
  timeout: 15
  expiry_warning:
    critical: 7
    warning: 30
  test_versions: ["TLSv1.2", "TLSv1.3"]
  check_weak_ciphers: true

# WHOIS Settings
whois:
  timeout: 20
  use_system_fallback: true
  custom_servers: {}
  deep_lookup: false

# WAF Detection Settings
waf:
  timeout: 15
  use_wafw00f: true
  wafw00f_timeout: 60
  http:
    user_agent: "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"
    follow_redirects: true
    max_redirects: 5
    verify_ssl: false
  test_payloads:
    - "' OR '1'='1"
    - "<script>alert(1)</script>"
    - "../../etc/passwd"
    - "UNION SELECT"

# Web Reconnaissance Settings
web_recon:
  wordlists:
    - "/usr/share/wordlists/dirb/common.txt"
    - "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt"
    - "/home/admin-1/Desktop/common.txt"
    - "./wordlists/common.txt"
  default_extensions: "php,html,htm,asp,aspx,jsp,js,txt,xml,json,bak,old,zip,tar.gz"
  ffuf:
    threads: 40
    timeout: 10
    rate_limit: 0
    follow_redirects: false
    match_codes: "200,204,301,302,307,401,403,405,500"
    filter_size: ""
    filter_words: ""
    headers: {}
  recursive_scan: false
  recursive_depth: 2

# Reporting Settings
reporting:
  output_dir: "./reports"
  naming_convention: "both"
  auto_open_reports: false
  include_screenshots: false
  template_dir: "./templates"
  custom_css: ""
  retention_days: 90

# Network Settings
network:
  proxy:
    enabled: false
    http_proxy: ""
    https_proxy: ""
    no_proxy: "localhost,127.0.0.1"
  dns_servers: []
  source_ip: ""
  rate_limit:
    enabled: false
    requests_per_second: 10

# Security Settings
security:
  safe_mode: false
  allowed_networks:
    - "10.0.0.0/8"
    - "172.16.0.0/12"
    - "192.168.0.0/16"
    - "127.0.0.0/8"
  blocked_networks: []
  confirm_external_scans: true
'''
    
    try:
        # Ensure directory exists
        DEFAULT_CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
        
        with open(DEFAULT_CONFIG_PATH, 'w') as f:
            f.write(default_config_content)
        typer.echo(f"[+] Default configuration created at {DEFAULT_CONFIG_PATH}")
        typer.echo("You can now edit this file to customize your settings.")
        typer.echo("\nTest your config with:")
        typer.echo("  pentoolkit config validate")
    except Exception as e:
        typer.echo(f"[!] Failed to create config file: {e}")


@config_app.command("test-wordlist")
def test_wordlist():
    """Test if configured wordlists are accessible."""
    config = get_config()
    web_config = config.web_recon_config
    
    typer.echo("Testing wordlist accessibility:")
    for i, wordlist_path in enumerate(web_config.wordlists, 1):
        expanded_path = os.path.expanduser(wordlist_path)
        if os.path.exists(expanded_path):
            size = os.path.getsize(expanded_path)
            typer.echo(f"  {i}. ✓ {wordlist_path} ({size:,} bytes)")
        else:
            typer.echo(f"  {i}. ✗ {wordlist_path} (not found)")
    
    # Show which one will be used
    active_wordlist = config.find_wordlist(web_config.wordlists)
    if active_wordlist:
        typer.echo(f"\n[+] Active wordlist: {active_wordlist}")
    else:
        typer.echo("\n[!] No wordlists found - web reconnaissance will fail!")

config_app = typer.Typer(help="Configuration management")
app.add_typer(config_app, name="config")

@config_app.command("test")
def test_config():
    """Test config system."""
    config = get_config()
    typer.echo("Config system working!")
    
    
@config_app.command("create")
def create_config():
    """Create default config file."""
    config_content = '''# Pentoolkit Configuration
web_recon:
  wordlists:
    - "/usr/share/wordlists/dirb/common.txt"
    - "/home/admin-1/Desktop/common.txt"
  default_extensions: "php,html,htm,asp,aspx,jsp"

nmap:
  default_args: "-sV"
  timeout: 300

ssl:
  default_port: 443
  timeout: 15
'''
    
    # Create in project root
    config_path = Path("./config.yaml")
    with open(config_path, 'w') as f:
        f.write(config_content)
    typer.echo(f"✅ Created config file: {config_path}")

@config_app.command("show")
def show_config():
    """Show current config."""
    config = get_config()
    typer.echo(f"Config path: {config.config_path}")
    if config.config_path.exists():
        typer.echo("✅ Config file exists")
        with open(config.config_path) as f:
            typer.echo(f.read())
    else:
        typer.echo("❌ Config file missing - run 'pentoolkit config create'")
        
# Add to your cli.py config section
@config_app.command("validate")
def validate_config():
    """Validate current configuration."""
    config = get_config()
    typer.echo("✅ Configuration validation passed!")
    typer.echo(f"Config loaded from: {config.config_path}")

@config_app.command("test-wordlist")
def test_wordlist():
    """Test if wordlists exist."""
    import os
    wordlists = [
        "/usr/share/wordlists/dirb/common.txt",
        "/home/admin-1/Desktop/common.txt"
    ]
    
    for wl in wordlists:
        if os.path.exists(wl):
            typer.echo(f"✅ {wl}")
        else:
            typer.echo(f"❌ {wl} (not found)")

if __name__ == "__main__":
    app()