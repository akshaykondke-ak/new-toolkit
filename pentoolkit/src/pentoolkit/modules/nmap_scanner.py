# pentoolkit/modules/nmap_scanner.py
import subprocess
import shlex
import nmap
from pentoolkit.utils import report
from pentoolkit.utils.config import get_config
from rich.console import Console
from rich.table import Table
from collections import Counter

console = Console()


def _run_nmap_raw_xml(target: str, args: str, timeout: int = 300) -> str | None:
    """
    Run system 'nmap' to produce XML to stdout and return it as text.
    Falls back to None on failure.
    """
    # Build command: nmap <args> -oX -
    # Keep target near front for readability
    cmd = f"nmap {target} {args} -oX -"
    try:
        completed = subprocess.run(
            shlex.split(cmd),
            capture_output=True,
            text=True,
            timeout=timeout
        )
        if completed.returncode == 0 or completed.stdout:
            return completed.stdout
        else:
            return None
    except subprocess.TimeoutExpired:
        console.print(f"[yellow]Nmap scan timed out after {timeout} seconds[/yellow]")
        return None
    except Exception as e:
        # Do not crash the whole scan if subprocess fails
        console.print(f"[!] Could not get raw nmap XML via subprocess: {e}")
        return None


def scan(target: str, scan_type: str = None, nse: str = None, extra_args: str = ""):
    """
    Perform nmap scan with configuration integration.
    
    Args:
        target: Target host/IP to scan
        scan_type: Scan type from config or custom
        nse: NSE scripts to run
        extra_args: Additional nmap arguments
    """
    # Get configuration
    config = get_config()
    nmap_config = config.nmap_config
    
    # Validate target network if security is enabled
    if not config.validate_target_network(target):
        console.print(f"[red]Target {target} is not in allowed network ranges[/red]")
        console.print("[yellow]Check security.allowed_networks in config.yaml[/yellow]")
        return []
    
    console.print(f"[bold blue][Nmap][/bold blue] Scanning {target}...")

    nm = nmap.PortScanner()
    
    # Determine scan arguments
    if scan_type and scan_type in nmap_config.scan_types:
        nmap_args = nmap_config.scan_types[scan_type]
        console.print(f"[cyan]Using scan type '{scan_type}': {nmap_args}[/cyan]")
    elif scan_type:
        # Custom scan type not in config
        nmap_args = scan_type
        console.print(f"[cyan]Using custom scan type: {nmap_args}[/cyan]")
    else:
        # Use default from config
        nmap_args = nmap_config.default_args
        console.print(f"[cyan]Using default scan: {nmap_args}[/cyan]")

    # Add NSE scripts
    if nse:
        nmap_args += f" --script {nse}"
    elif nmap_config.default_nse_scripts:
        nmap_args += f" --script {nmap_config.default_nse_scripts}"
        console.print(f"[cyan]Using default NSE scripts: {nmap_config.default_nse_scripts}[/cyan]")

    # Add host timeout from config
    if nmap_config.host_timeout:
        nmap_args += f" --host-timeout {nmap_config.host_timeout}s"
    
    # Add ping skip if configured
    if nmap_config.skip_ping:
        nmap_args += " -Pn"
        console.print("[cyan]Skipping ping (host discovery disabled)[/cyan]")

    # Include any extra arguments
    if extra_args:
        nmap_args += f" {extra_args}"

    # Trim and normalize args
    nmap_args = nmap_args.strip()
    
    console.print(f"[cyan]Final nmap command: nmap {target} {nmap_args}[/cyan]")

    # Try running python-nmap first
    scan_successful = False
    try:
        nm.scan(target, arguments=nmap_args)
        scan_successful = True
        console.print("[green]Nmap scan completed successfully[/green]")
    except Exception as e:
        console.print(f"[red]Nmap scan (python-nmap) failed: {e}[/red]")
        console.print("[yellow]Attempting to capture raw XML output...[/yellow]")

    open_ports = []

    if scan_successful:
        try:
            # Loop through all hosts and their protocols
            for host in nm.all_hosts():
                host_state = nm[host].state()
                console.print(f"[cyan]Host {host} is {host_state}[/cyan]")
                
                for proto in nm[host].all_protocols():
                    ports = nm[host][proto].keys()
                    for port in ports:
                        port_info = nm[host][proto][port]
                        state = port_info.get('state', 'unknown')
                        service = port_info.get('name', 'unknown')
                        product = port_info.get('product', '')
                        version = port_info.get('version', '')
                        extrainfo = port_info.get('extrainfo', '')

                        if state == "open":  # only log open ports
                            open_ports.append({
                                "host": host,
                                "port": port,
                                "protocol": proto,
                                "service": service,
                                "product": product,
                                "version": version,
                                "extrainfo": extrainfo,
                                "state": state
                            })
        except Exception as e:
            console.print(f"[red]Error parsing python-nmap results: {e}[/red]")

    # --- Capture raw XML using system nmap (best effort) ---
    raw_xml = _run_nmap_raw_xml(target, nmap_args, nmap_config.timeout)
    if raw_xml:
        # Save raw xml alongside other reports
        report.save_raw(target, "nmap", raw_xml)
        console.print("[green]Raw XML output saved[/green]")

    # Build a service summary (counts by service name)
    service_counts = Counter([p["service"] for p in open_ports])

    # Print results nicely (rich table)
    if open_ports:
        table = Table(title=f"Nmap Scan Results for {target}")
        table.add_column("Host", justify="center")
        table.add_column("Port", justify="center")
        table.add_column("Protocol")
        table.add_column("Service")
        table.add_column("Product")
        table.add_column("Version")
        table.add_column("State", justify="center")

        for p in open_ports:
            state_color = "green" if p["state"] == "open" else "red"
            product_version = f"{p['product']} {p['version']}".strip()
            
            table.add_row(
                p.get("host", target),
                str(p["port"]),
                p["protocol"],
                p["service"],
                product_version or "-",
                p.get("extrainfo", "") or "-",
                f"[{state_color}]{p['state']}[/{state_color}]"
            )

        console.print(table)
        
        # Print service summary
        if service_counts:
            console.print("\n[bold]Service Summary:[/bold]")
            for service, count in service_counts.most_common():
                console.print(f"  • {service}: {count} port(s)")
                
    else:
        console.print(f"[yellow]No open ports found on {target}[/yellow]")

    # Build data structure for reporting
    data = {
        "target": target,
        "scan_type": scan_type or "default",
        "open_ports": open_ports,
        "service_summary": dict(service_counts),
        "nmap_args": nmap_args,
        "total_open_ports": len(open_ports),
        "config_used": {
            "timeout": nmap_config.timeout,
            "host_timeout": nmap_config.host_timeout,
            "skip_ping": nmap_config.skip_ping,
            "default_nse_scripts": nmap_config.default_nse_scripts
        }
    }

    # Save reports if we have results or raw data
    if open_ports or raw_xml:
        report.save_report(data, target, "nmap")
        report.save_report_html(data, target, "nmap")
        console.print("[green]Reports saved successfully[/green]")

    return open_ports