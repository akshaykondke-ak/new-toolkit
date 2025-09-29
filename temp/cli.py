# pentoolkit/src/pentoolkit/cli.py
import typer
import os
import yaml
import json
import sqlite3
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional, List
from rich.console import Console
from rich.table import Table
from rich.prompt import Prompt, Confirm
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
from rich.panel import Panel
from rich.columns import Columns
import http.server
import socketserver
import webbrowser
import time

from pentoolkit import main
from pentoolkit.utils import report
from pentoolkit.utils.config import get_config, reload_config, DEFAULT_CONFIG_PATH

console = Console()

# Initialize Typer app with better help
app = typer.Typer(
    help="🛡️  Pentoolkit - Professional Penetration Testing Automation Suite",
    no_args_is_help=True,
    rich_markup_mode="rich"
)

# Command groups
scan_app = typer.Typer(help="🎯 Run security scans")
results_app = typer.Typer(help="📊 Manage and view scan results") 
config_app = typer.Typer(help="⚙️  Configuration management")
admin_app = typer.Typer(help="🔧 Administrative tools")

app.add_typer(scan_app, name="scan")
app.add_typer(results_app, name="results")
app.add_typer(config_app, name="config")
app.add_typer(admin_app, name="admin")

# Database setup for scan tracking
DB_PATH = Path("./pentoolkit_scans.db")

def init_database():
    """Initialize SQLite database for scan tracking"""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target TEXT NOT NULL,
            modules TEXT NOT NULL,
            status TEXT NOT NULL,
            start_time TEXT NOT NULL,
            end_time TEXT,
            results_path TEXT,
            notes TEXT
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS scan_results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER,
            module TEXT NOT NULL,
            result_data TEXT NOT NULL,
            FOREIGN KEY (scan_id) REFERENCES scans (id)
        )
    ''')
    
    conn.commit()
    conn.close()

def log_scan_start(target: str, modules: str) -> int:
    """Log scan start and return scan ID"""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    cursor.execute('''
        INSERT INTO scans (target, modules, status, start_time)
        VALUES (?, ?, ?, ?)
    ''', (target, modules, 'running', datetime.utcnow().isoformat()))
    
    scan_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return scan_id

def log_scan_complete(scan_id: int, results_path: str = None):
    """Mark scan as complete"""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    cursor.execute('''
        UPDATE scans 
        SET status = ?, end_time = ?, results_path = ?
        WHERE id = ?
    ''', ('completed', datetime.utcnow().isoformat(), results_path, scan_id))
    
    conn.commit()
    conn.close()

# ===================== SCAN COMMANDS =====================

@scan_app.command("run")
def run_scan(
    target: str = typer.Argument(..., help="Target hostname or URL (e.g., example.com)"),
    modules: str = typer.Option(
        "all",
        "--modules", "-m",
        help="Modules to run: nmap,ssl,whois,waf,web_recon or 'all'"
    ),
    scan_type: str = typer.Option(
        "default", 
        "--scan-type", "-s",
        help="Nmap scan type: default,syn,udp,aggressive,stealth,discovery"
    ),
    ports: str = typer.Option(
        None,
        "--ports", "-p", 
        help="Port specification (e.g., '1-1000', '80,443,8080')"
    ),
    scripts: str = typer.Option(
        None,
        "--scripts",
        help="NSE scripts to run (e.g., 'vuln,auth,discovery')"
    ),
    timing: int = typer.Option(
        None,
        "--timing", "-T",
        help="Nmap timing template (0-5, higher = faster/noisier)"
    ),
    output: str = typer.Option(
        "both",
        "--output", "-o",
        help="Output format: json, html, both"
    ),
    auto_aggregate: bool = typer.Option(
        True,
        "--auto-aggregate/--no-auto-aggregate",
        help="Automatically create summary report"
    ),
    verbose: bool = typer.Option(
        False,
        "--verbose", "-v",
        help="Enable verbose output"
    )
):
    """
    🎯 Run comprehensive security scans against a target
    
    Examples:
      pentoolkit scan run scanme.nmap.org
      pentoolkit scan run example.com -m nmap,ssl --scan-type aggressive
      pentoolkit scan run 192.168.1.1 -p 1-1000 --scripts vuln
    """
    init_database()
    
    # Validate target
    if not target:
        console.print("[red]❌ Target cannot be empty[/red]")
        raise typer.Exit(1)
    
    # Show scan configuration
    config_panel = Panel.fit(
        f"🎯 [bold]Target:[/bold] {target}\n"
        f"📋 [bold]Modules:[/bold] {modules}\n" 
        f"🔍 [bold]Scan Type:[/bold] {scan_type}\n"
        f"🚪 [bold]Ports:[/bold] {ports or 'default'}\n"
        f"📜 [bold]Scripts:[/bold] {scripts or 'default'}\n"
        f"⏱️  [bold]Timing:[/bold] {timing or 'default'}\n"
        f"💾 [bold]Output:[/bold] {output}",
        title="Scan Configuration",
        border_style="blue"
    )
    console.print(config_panel)
    
    if not Confirm.ask("🚀 Proceed with scan?"):
        console.print("[yellow]Scan cancelled by user[/yellow]")
        raise typer.Exit(0)
    
    # Start scan tracking
    scan_id = log_scan_start(target, modules)
    
    # Build custom arguments for nmap
    custom_nmap_args = []
    if ports:
        custom_nmap_args.append(f"-p {ports}")
    if scripts:
        custom_nmap_args.append(f"--script {scripts}")
    if timing is not None:
        custom_nmap_args.append(f"-T{timing}")
    
    extra_args = " ".join(custom_nmap_args)
    
    try:
        # Run scans with progress tracking
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TimeElapsedColumn(),
            console=console
        ) as progress:
            task = progress.add_task("🔍 Running scans...", total=None)
            
            if verbose:
                console.print(f"[dim]Running with extra args: {extra_args}[/dim]")
            
            results = main.run_scan(
                target, 
                modules, 
                scan_type=scan_type, 
                extra_args=extra_args
            )
            
            progress.update(task, description="✅ Scans completed!")
        
        # Show results summary
        show_scan_summary(results, target)
        
        # Auto-aggregate if requested
        if auto_aggregate:
            console.print("\n[cyan]📊 Generating aggregated report...[/cyan]")
            summary_data, html_path = report.aggregate_target_reports(target)
            if html_path:
                console.print(f"[green]✅ Summary report: {html_path}[/green]")
        
        # Log completion
        log_scan_complete(scan_id, html_path if auto_aggregate else None)
        
        console.print(f"\n[green]🎉 Scan completed successfully![/green]")
        console.print(f"[dim]Scan ID: {scan_id}[/dim]")
        
    except KeyboardInterrupt:
        console.print("\n[yellow]⚠️  Scan interrupted by user[/yellow]")
        log_scan_complete(scan_id)
        raise typer.Exit(1)
    except Exception as e:
        console.print(f"\n[red]❌ Scan failed: {e}[/red]")
        log_scan_complete(scan_id)
        raise typer.Exit(1)

@scan_app.command("interactive")
def interactive_scan():
    """🎮 Interactive scan builder with guided prompts"""
    console.print(Panel.fit(
        "🎮 [bold blue]Interactive Scan Builder[/bold blue]\n"
        "This will guide you through creating a custom scan",
        border_style="blue"
    ))
    
    # Gather target
    target = Prompt.ask("🎯 Enter target (hostname/IP)")
    
    # Module selection
    available_modules = ["nmap", "ssl", "whois", "waf", "web_recon"]
    console.print("\n📋 Available modules:")
    for i, module in enumerate(available_modules, 1):
        console.print(f"  {i}. {module}")
    
    module_choice = Prompt.ask(
        "Select modules (comma-separated numbers or 'all')",
        default="all"
    )
    
    if module_choice.lower() == 'all':
        modules = "all"
    else:
        try:
            indices = [int(x.strip()) - 1 for x in module_choice.split(',')]
            modules = ",".join([available_modules[i] for i in indices])
        except (ValueError, IndexError):
            console.print("[red]Invalid selection, using all modules[/red]")
            modules = "all"
    
    # Nmap configuration
    if 'nmap' in modules or modules == 'all':
        console.print("\n🔍 Nmap Configuration:")
        scan_types = ["default", "syn", "udp", "aggressive", "stealth", "discovery"]
        
        console.print("Available scan types:")
        for i, stype in enumerate(scan_types, 1):
            console.print(f"  {i}. {stype}")
        
        scan_type_idx = Prompt.ask("Choose scan type", default="1")
        try:
            scan_type = scan_types[int(scan_type_idx) - 1]
        except (ValueError, IndexError):
            scan_type = "default"
        
        ports = Prompt.ask("🚪 Port range (e.g., '1-1000', '80,443')", default="")
        scripts = Prompt.ask("📜 NSE scripts (e.g., 'vuln,auth')", default="")
        timing = Prompt.ask("⏱️  Timing (0-5)", default="3")
    else:
        scan_type = "default"
        ports = ""
        scripts = ""
        timing = "3"
    
    # Show final configuration
    config_summary = f"""
🎯 Target: {target}
📋 Modules: {modules}
🔍 Scan Type: {scan_type}
🚪 Ports: {ports or 'default'}
📜 Scripts: {scripts or 'default'}
⏱️  Timing: {timing}
    """
    
    console.print(Panel(config_summary.strip(), title="Final Configuration"))
    
    if Confirm.ask("🚀 Start scan with this configuration?"):
        # Build command arguments
        cmd_args = [target, "--modules", modules, "--scan-type", scan_type]
        if ports:
            cmd_args.extend(["--ports", ports])
        if scripts:
            cmd_args.extend(["--scripts", scripts])
        if timing != "3":
            cmd_args.extend(["--timing", timing])
        
        # Execute the scan
        ctx = typer.Context(run_scan)
        ctx.invoke(run_scan, target=target, modules=modules, scan_type=scan_type, 
                  ports=ports, scripts=scripts, timing=int(timing))
    else:
        console.print("[yellow]Scan cancelled[/yellow]")

def show_scan_summary(results: dict, target: str):
    """Display a nice summary of scan results"""
    if not results:
        console.print("[yellow]No results to display[/yellow]")
        return
    
    # Create summary table
    table = Table(title=f"Scan Results Summary - {target}")
    table.add_column("Module", style="bold cyan")
    table.add_column("Status", justify="center")
    table.add_column("Key Findings", style="dim")
    
    for module, result in results.items():
        if result:
            status = "[green]✅ Success[/green]"
            
            # Module-specific summaries
            if module == "nmap":
                findings = f"{len(result)} open ports found" if isinstance(result, list) else "Scan completed"
            elif module == "ssl":
                findings = f"SSL service on port {result.get('port', 'unknown')}" if isinstance(result, dict) else "SSL analysis completed"
            elif module == "web_recon":
                findings = f"{len(result.get('results', []))} paths discovered" if isinstance(result, dict) else "Web recon completed"
            else:
                findings = "Scan completed"
        else:
            status = "[red]❌ Failed[/red]"
            findings = "No results"
        
        table.add_row(module.upper(), status, findings)
    
    console.print(table)

# ===================== RESULTS COMMANDS =====================

@results_app.command("list")
def list_results(
    target: str = typer.Option(None, help="Filter by target"),
    days: int = typer.Option(30, help="Show results from last N days"),
    status: str = typer.Option(None, help="Filter by status: running, completed, failed")
):
    """📊 List recent scan results"""
    init_database()
    
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # Build query
    query = """
        SELECT id, target, modules, status, start_time, end_time, results_path
        FROM scans 
        WHERE start_time > ?
    """
    params = [(datetime.utcnow() - timedelta(days=days)).isoformat()]
    
    if target:
        query += " AND target LIKE ?"
        params.append(f"%{target}%")
    
    if status:
        query += " AND status = ?"
        params.append(status)
    
    query += " ORDER BY start_time DESC"
    
    cursor.execute(query, params)
    results = cursor.fetchall()
    conn.close()
    
    if not results:
        console.print("[yellow]No scan results found[/yellow]")
        return
    
    # Display results table
    table = Table(title=f"Recent Scan Results ({len(results)} found)")
    table.add_column("ID", justify="center")
    table.add_column("Target", style="bold")
    table.add_column("Modules")
    table.add_column("Status", justify="center")
    table.add_column("Started", style="dim")
    table.add_column("Duration", justify="center")
    
    for row in results:
        scan_id, target, modules, status, start_time, end_time, results_path = row
        
        # Calculate duration
        if end_time:
            start_dt = datetime.fromisoformat(start_time)
            end_dt = datetime.fromisoformat(end_time)
            duration = str(end_dt - start_dt).split('.')[0]  # Remove microseconds
        else:
            duration = "Running..."
        
        # Status styling
        if status == "completed":
            status_display = "[green]✅ Completed[/green]"
        elif status == "running":
            status_display = "[yellow]🔄 Running[/yellow]"
        else:
            status_display = "[red]❌ Failed[/red]"
        
        # Format start time
        start_dt = datetime.fromisoformat(start_time)
        start_display = start_dt.strftime("%m-%d %H:%M")
        
        table.add_row(
            str(scan_id),
            target,
            modules,
            status_display,
            start_display,
            duration
        )
    
    console.print(table)

@results_app.command("show")
def show_result(scan_id: int = typer.Argument(..., help="Scan ID to display")):
    """🔍 Show detailed results for a specific scan"""
    init_database()
    
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    cursor.execute("""
        SELECT target, modules, status, start_time, end_time, results_path, notes
        FROM scans WHERE id = ?
    """, (scan_id,))
    
    result = cursor.fetchone()
    if not result:
        console.print(f"[red]Scan ID {scan_id} not found[/red]")
        raise typer.Exit(1)
    
    target, modules, status, start_time, end_time, results_path, notes = result
    
    # Display scan details
    details_panel = Panel.fit(
        f"🎯 [bold]Target:[/bold] {target}\n"
        f"📋 [bold]Modules:[/bold] {modules}\n"
        f"📊 [bold]Status:[/bold] {status}\n"
        f"🕒 [bold]Started:[/bold] {start_time}\n"
        f"🏁 [bold]Completed:[/bold] {end_time or 'N/A'}\n"
        f"📁 [bold]Results:[/bold] {results_path or 'N/A'}\n"
        f"📝 [bold]Notes:[/bold] {notes or 'None'}",
        title=f"Scan Details - ID {scan_id}",
        border_style="blue"
    )
    console.print(details_panel)
    
    # Show results files
    target_reports = report.find_target_reports(target)
    if target_reports:
        console.print("\n📁 Available Reports:")
        for report_file in target_reports:
            console.print(f"  • {report_file}")
    
    conn.close()

@results_app.command("dashboard")
def results_dashboard(
    port: int = typer.Option(8080, help="Port for dashboard server")
):
    """🌐 Launch web-based results dashboard"""
    console.print(f"[cyan]🚀 Starting results dashboard on port {port}...[/cyan]")
    
    # For now, use the existing report server
    # TODO: Create a proper dashboard with scan history, search, etc.
    report_dir = report.REPORT_DIR if hasattr(report, "REPORT_DIR") else "./reports"
    report_dir = os.path.abspath(report_dir)
    
    if not os.path.exists(report_dir):
        console.print(f"[red]Reports directory not found: {report_dir}[/red]")
        raise typer.Exit(1)
    
    console.print(f"[green]📊 Dashboard available at: http://localhost:{port}/[/green]")
    os.chdir(report_dir)
    
    Handler = http.server.SimpleHTTPRequestHandler
    with socketserver.TCPServer(("", port), Handler) as httpd:
        try:
            webbrowser.open(f"http://localhost:{port}/")
            httpd.serve_forever()
        except KeyboardInterrupt:
            console.print("\n[yellow]Dashboard stopped[/yellow]")

@results_app.command("search")
def search_results(
    query: str = typer.Argument(..., help="Search query (target name, module, etc.)"),
    days: int = typer.Option(30, help="Search within last N days")
):
    """🔍 Search scan results"""
    init_database()
    
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    cursor.execute("""
        SELECT id, target, modules, status, start_time
        FROM scans 
        WHERE (target LIKE ? OR modules LIKE ?)
        AND start_time > ?
        ORDER BY start_time DESC
    """, (f"%{query}%", f"%{query}%", (datetime.utcnow() - timedelta(days=days)).isoformat()))
    
    results = cursor.fetchall()
    conn.close()
    
    if not results:
        console.print(f"[yellow]No results found for '{query}'[/yellow]")
        return
    
    console.print(f"[green]Found {len(results)} results for '{query}':[/green]")
    for scan_id, target, modules, status, start_time in results:
        start_dt = datetime.fromisoformat(start_time)
        console.print(f"  {scan_id}: {target} ({modules}) - {status} - {start_dt.strftime('%Y-%m-%d %H:%M')}")

# ===================== CONFIG COMMANDS =====================

@config_app.command("show")
def show_config(
    section: str = typer.Option(None, help="Show specific section")
):
    """⚙️ Show current configuration"""
    config = get_config()
    
    console.print(Panel.fit(
        f"📁 [bold]Config File:[/bold] {config.config_path}\n"
        f"✅ [bold]Status:[/bold] {'Found' if config.config_path.exists() else 'Not Found'}",
        title="Configuration Status",
        border_style="green" if config.config_path.exists() else "red"
    ))
    
    if section:
        section_data = config.get_section(section)
        if section_data:
            console.print(f"\n[bold blue][{section}] Section:[/bold blue]")
            console.print(yaml.dump({section: section_data}, default_flow_style=False))
        else:
            console.print(f"[red]Section '{section}' not found[/red]")
    else:
        if config._config_data:
            console.print("\n[bold]Available Sections:[/bold]")
            for section_name in config._config_data.keys():
                console.print(f"  • {section_name}")
            console.print("\n[dim]Use --section <name> to view specific section[/dim]")
        else:
            console.print("[yellow]Using default configuration (no config file found)[/yellow]")

@config_app.command("create")
def create_config(
    force: bool = typer.Option(False, "--force", help="Overwrite existing config")
):
    """📝 Create default configuration file"""
    if DEFAULT_CONFIG_PATH.exists() and not force:
        if not Confirm.ask(f"Config file exists at {DEFAULT_CONFIG_PATH}. Overwrite?"):
            console.print("[yellow]Cancelled[/yellow]")
            raise typer.Exit(0)
    
    # Create default config (use the comprehensive one from the documents)
    default_config = '''# Pentoolkit Configuration File
global:
  default_timeout: 30
  default_threads: 40
  output:
    colored_output: true
    log_level: INFO
    save_raw_output: true
    report_formats: both

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

ssl:
  default_port: 443
  additional_ports: [8443, 8080, 9443]
  timeout: 15
  expiry_warning:
    critical: 7
    warning: 30

web_recon:
  wordlists:
    - "/usr/share/wordlists/dirb/common.txt"
    - "/home/admin-1/Desktop/common.txt"
    - "./wordlists/common.txt"
  default_extensions: "php,html,htm,asp,aspx,jsp,js,txt"
  ffuf:
    threads: 40
    timeout: 10

security:
  safe_mode: false
  allowed_networks:
    - "10.0.0.0/8"
    - "172.16.0.0/12"
    - "192.168.0.0/16"
    - "127.0.0.0/8"
    - "0.0.0.0/0"  # Allow all networks
'''
    
    try:
        DEFAULT_CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
        with open(DEFAULT_CONFIG_PATH, 'w') as f:
            f.write(default_config)
        console.print(f"[green]✅ Configuration created at {DEFAULT_CONFIG_PATH}[/green]")
    except Exception as e:
        console.print(f"[red]❌ Failed to create config: {e}[/red]")
        raise typer.Exit(1)

@config_app.command("validate")
def validate_config():
    """✅ Validate current configuration"""
    config = get_config()
    issues = []
    
    console.print("[cyan]🔍 Validating configuration...[/cyan]")
    
    # Check wordlists
    web_config = config.web_recon_config
    found_wordlist = config.find_wordlist(web_config.wordlists)
    if found_wordlist:
        console.print(f"[green]✅ Wordlist found: {found_wordlist}[/green]")
    else:
        issues.append("No accessible wordlists found for web reconnaissance")
    
    # Check timeouts
    global_config = config.global_config
    if global_config.default_timeout >= 5:
        console.print(f"[green]✅ Default timeout: {global_config.default_timeout}s[/green]")
    else:
        issues.append(f"Default timeout very low: {global_config.default_timeout}s")
    
    # Show results
    if issues:
        console.print(f"\n[red]❌ Found {len(issues)} issues:[/red]")
        for issue in issues:
            console.print(f"  • {issue}")
        raise typer.Exit(1)
    else:
        console.print("\n[green]🎉 Configuration validation passed![/green]")

# ===================== ADMIN COMMANDS =====================

@admin_app.command("cleanup")
def cleanup_old_data(
    days: int = typer.Option(30, help="Remove data older than N days"),
    dry_run: bool = typer.Option(False, "--dry-run", help="Show what would be deleted")
):
    """🧹 Clean up old reports and scan data"""
    if dry_run:
        console.print(f"[yellow]🔍 Dry run - showing what would be deleted (older than {days} days)[/yellow]")
    else:
        if not Confirm.ask(f"⚠️  Delete all data older than {days} days?"):
            console.print("[yellow]Cancelled[/yellow]")
            raise typer.Exit(0)
    
    # Clean up reports
    removed = report.cleanup_old_reports(days)
    console.print(f"[green]🗑️  {'Would remove' if dry_run else 'Removed'} {removed} old reports[/green]")
    
    # Clean up database entries
    if not dry_run:
        init_database()
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        cutoff = (datetime.utcnow() - timedelta(days=days)).isoformat()
        cursor.execute("DELETE FROM scans WHERE start_time < ?", (cutoff,))
        db_removed = cursor.rowcount
        
        conn.commit()
        conn.close()
        
        console.print(f"[green]🗄️  Removed {db_removed} old database entries[/green]")

@admin_app.command("stats")
def show_statistics():
    """📈 Show system statistics"""
    init_database()
    
    # Database stats
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    cursor.execute("SELECT COUNT(*) FROM scans")
    total_scans = cursor.fetchone()[0]
    
    cursor.execute("SELECT COUNT(*) FROM scans WHERE status = 'completed'")
    completed_scans = cursor.fetchone()[0]
    
    cursor.execute("SELECT COUNT(*) FROM scans WHERE status = 'running'")
    running_scans = cursor.fetchone()[0]
    
    cursor.execute("SELECT target, COUNT(*) as count FROM scans GROUP BY target ORDER BY count DESC LIMIT 5")
    top_targets = cursor.fetchall()
    
    conn.close()
    
    # File stats
    report_stats = report.get_report_statistics()
    
    # Display stats
    stats_panel = Panel.fit(
        f"📊 [bold]Total Scans:[/bold] {total_scans}\n"
        f"✅ [bold]Completed:[/bold] {completed_scans}\n"
        f"🔄 [bold]Running:[/bold] {running_scans}\n"
        f"📁 [bold]Report Files:[/bold] {report_stats['total_reports']}\n"
        f"🎯 [bold]Unique Targets:[/bold] {report_stats['unique_targets']}\n"
        f"💾 [bold]Storage Used:[/bold] {report_stats['total_size_mb']} MB",
        title="System Statistics",
        border_style="green"
    )
    console.print(stats_panel)
    
    if top_targets:
        console.print("\n[bold]🎯 Most Scanned Targets:[/bold]")
        for target, count in top_targets:
            console.print(f"  • {target}: {count} scans")

# ===================== MAIN ENTRY POINT =====================

def main_cli():
    """Main entry point for the CLI"""
    app()   
if __name__ == "__main__":
    main_cli()  
    