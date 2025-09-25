# pentoolkit/test_run.py
from pentoolkit.modules import nmap_scanner, ssl_scanner, whois_lookup, waf_detector
from rich.console import Console

console = Console()

def test_target(target: str):
    console.rule(f"[bold blue]Testing Pentoolkit modules on {target}")

    # --- NMAP ---
    console.print("[bold]1. Nmap Scan[/bold]")
    nmap_result = nmap_scanner.scan(target)
    if nmap_result:
        console.print(f"[green]Nmap scan complete. {len(nmap_result)} open ports detected.[/green]")
    else:
        console.print("[yellow]No open ports found or Nmap failed.[/yellow]")

    # --- SSL ---
    console.print("[bold]2. SSL Scan[/bold]")
    ssl_result = ssl_scanner.scan(target)
    if ssl_result:
        console.print(f"[green]SSL scan complete. Version: {ssl_result.get('ssl_version')}[/green]")
    else:
        console.print("[yellow]SSL scan failed.[/yellow]")

    # --- WHOIS ---
    console.print("[bold]3. WHOIS Lookup[/bold]")
    whois_result = whois_lookup.lookup(target)
    if whois_result:
        console.print("[green]WHOIS lookup complete.[/green]")
    else:
        console.print("[yellow]WHOIS lookup failed.[/yellow]")

    # --- WAF ---
    console.print("[bold]4. WAF Detection[/bold]")
    waf_result = waf_detector.detect(target)
    if waf_result.get("waf_detected"):
        console.print(f"[red]WAF detected: {waf_result.get('waf_name', 'Unknown')}[/red]")
    else:
        console.print("[green]No WAF detected.[/green]")

    console.rule(f"[bold blue]Testing Completed for {target}")

if __name__ == "__main__":
    import sys
    if len(sys.argv) != 2:
        console.print("[red]Usage: python test_run.py <target>[/red]")
        sys.exit(1)

    target_host = sys.argv[1]
    test_target(target_host)
