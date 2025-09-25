# pentoolkit/modules/web_recon.py
import subprocess
import shlex
import os
from datetime import datetime
from pentoolkit.utils import report
from pentoolkit.utils.config import get_config, get_wordlist_path
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn
from pentoolkit.utils.config import get_config

console = Console()


def sanitize_target(target: str) -> str:
    """
    Make a filesystem-safe version of a URL/hostname:
    - strip scheme, replace slashes/colon with underscores
    - Example: https://rivedix.com -> rivedix.com
    """
    t = target.strip()
    if t.startswith("https://"):
        t = t[len("https://") :]
    elif t.startswith("http://"):
        t = t[len("http://") :]
    # replace path separators and colons with underscore
    t = t.replace("/", "_").replace(":", "_")
    return t


def run_ffuf(
    target: str,
    wordlist: str = None,
    extensions: str = None,
    threads: int = None,
    timeout: int = None,
):
    """
    Run ffuf against a target and save JSON + HTML reports.
    
    Parameters now use config defaults if not specified.
    Returns: parsed JSON output (dict) or None on failure.
    """
    # Get configuration
    from pentoolkit.utils.config import get_config
    config = get_config()
    web_config = config.get_section("web_recon", {})
    
    # Use config defaults if parameters not provided
    if wordlist is None:
        wordlists = web_config.get("wordlists", ["/usr/share/wordlists/dirb/common.txt"])
        for wl in wordlists:
            if os.path.exists(wl):
                wordlist = wl
                break
        if wordlist is None:
            wordlist = "/usr/share/wordlists/dirb/common.txt"  # fallback
    
    if extensions is None:
        extensions = web_config.get("default_extensions", "php,html,htm,asp,aspx,jsp")
    
    if threads is None:
        threads = 40  # default
    
    if timeout is None:
        timeout = 10  # default
    
    console.print(f"[bold blue][WebRecon][/bold blue] Running ffuf on {target}")
    console.print(f"[cyan]Using wordlist:[/cyan] {wordlist}")
    console.print(f"[cyan]Extensions:[/cyan] {extensions}")
    console.print(f"[cyan]Threads:[/cyan] {threads}, [cyan]Timeout:[/cyan] {timeout}s")

    # Rest of your existing function code continues here...

def print_ffuf_table(data: dict, target: str):
    """Pretty-print top results of ffuf scan in a Rich table."""
    if not data or "results" not in data or not data.get("results"):
        console.print("[yellow]No results found.[/yellow]")
        return

    results = data.get("results", [])
    
    # Get config for display limits
    config = get_config()
    global_config = config.global_config
    
    table = Table(title=f"Web Recon Results - {target}")
    table.add_column("URL", style="cyan", overflow="fold")
    table.add_column("Status", style="green")
    table.add_column("Length", justify="right")
    table.add_column("Words", justify="right")
    table.add_column("Lines", justify="right")

    # Show results (limit to first 20 for readability)
    display_count = min(len(results), 20)
    for item in results[:display_count]:
        status_code = item.get("status", "-")
        status_style = "green" if str(status_code).startswith("2") else "yellow" if str(status_code).startswith("3") else "red"
        
        table.add_row(
            item.get("url", "-"),
            f"[{status_style}]{status_code}[/{status_style}]",
            str(item.get("length", "-")),
            str(item.get("words", "-")),
            str(item.get("lines", "-")),
        )

    console.print(table)
    
    if len(results) > display_count:
        console.print(f"[cyan]... and {len(results) - display_count} more results (see full report)[/cyan]")
    
    # Show summary stats
    console.print(f"[green]Total results found: {len(results)}[/green]")
    
    # Show config info used
    config_used = data.get("config_used", {})
    if config_used:
        console.print(f"[dim]Wordlist: {config_used.get('wordlist', 'N/A')}[/dim]")
        console.print(f"[dim]Threads: {config_used.get('threads', 'N/A')}, Timeout: {config_used.get('timeout', 'N/A')}s[/dim]")


if __name__ == "__main__":
    target_host = input("Enter target URL (e.g., https://example.com): ").strip()
    run_ffuf(target_host)