# pentoolkit/modules/web_recon.py
import subprocess
import shlex
import os
import json
from datetime import datetime
from typing import Dict, List, Optional, Any
from pentoolkit.utils import report
from pentoolkit.utils.config import get_config, get_wordlist_path
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn

console = Console()

def sanitize_target(target: str) -> str:
    """
    Make a filesystem-safe version of a URL/hostname:
    - strip scheme, replace slashes/colon with underscores
    - Example: https://rivedix.com -> rivedix.com
    """
    t = target.strip()
    if t.startswith("https://"):
        t = t[len("https://"):]
    elif t.startswith("http://"):
        t = t[len("http://"):]
    # replace path separators and colons with underscore
    t = t.replace("/", "_").replace(":", "_")
    return t

def ensure_target_has_protocol(target: str) -> str:
    """Ensure target has http/https protocol"""
    if not target.startswith(("http://", "https://")):
        # Try HTTPS first, fallback to HTTP
        return f"https://{target}"
    return target

def run_ffuf(
    target: str,
    wordlist: str = None,
    extensions: str = None,
    threads: int = None,
    timeout: int = None,
    rate_limit: int = None,
    match_codes: str = None
) -> Optional[Dict]:
    """
    Run ffuf against a target and save JSON + HTML reports.
    
    Parameters use config defaults if not specified.
    Returns: parsed JSON output (dict) or None on failure.
    """
    # Get configuration
    config = get_config()
    web_config = config.web_recon_config
    
    # Use config defaults if parameters not provided
    if wordlist is None:
        wordlist = config.find_wordlist(web_config.wordlists)
        if not wordlist:
            console.print("[red]No accessible wordlist found![/red]")
            console.print("Available paths checked:")
            for wl in web_config.wordlists:
                console.print(f"  - {wl}")
            return None
    
    if extensions is None:
        extensions = web_config.default_extensions
    
    if threads is None:
        threads = web_config.ffuf.get("threads", 40)
    
    if timeout is None:
        timeout = web_config.ffuf.get("timeout", 10)
    
    if rate_limit is None:
        rate_limit = web_config.ffuf.get("rate_limit", 0)
    
    if match_codes is None:
        match_codes = web_config.ffuf.get("match_codes", "200,204,301,302,307,401,403,405,500")
    
    # Ensure target has protocol
    target_url = ensure_target_has_protocol(target)
    
    console.print(f"[bold blue][WebRecon][/bold blue] Running ffuf on {target_url}")
    console.print(f"[cyan]Using wordlist:[/cyan] {wordlist}")
    console.print(f"[cyan]Extensions:[/cyan] {extensions}")
    console.print(f"[cyan]Threads:[/cyan] {threads}, [cyan]Timeout:[/cyan] {timeout}s")
    
    # Verify wordlist exists
    if not os.path.exists(wordlist):
        console.print(f"[red]Wordlist not found: {wordlist}[/red]")
        return None
    
    # Check if ffuf is available
    try:
        subprocess.run(["ffuf", "-h"], capture_output=True, check=True)
    except (subprocess.CalledProcessError, FileNotFoundError):
        console.print("[red]ffuf not found! Install with: go install github.com/ffuf/ffuf@latest[/red]")
        return None
    
    # Prepare ffuf command
    safe_target = sanitize_target(target)
    timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    output_file = f"/tmp/{safe_target}_ffuf_{timestamp}.json"
    
    # Build ffuf command
    # Use FUZZ placeholder for directory/file fuzzing
    if not target_url.endswith('/'):
        target_url += '/'
    fuzz_url = f"{target_url}FUZZ"
    
    cmd_parts = [
        "ffuf",
        "-w", wordlist,
        "-u", fuzz_url,
        "-t", str(threads),
        "-timeout", str(timeout),
        "-mc", match_codes,
        "-o", output_file,
        "-of", "json",
        "-s"  # Silent mode (less verbose output)
    ]
    
    # Add extensions if specified
    if extensions:
        # For extensions, we need to add them to the FUZZ keyword
        ext_list = [ext.strip() for ext in extensions.split(',')]
        if ext_list:
            # Create extension wordlist
            ext_file = f"/tmp/extensions_{timestamp}.txt"
            with open(ext_file, 'w') as f:
                # Add empty extension (for directories)
                f.write("\n")
                # Add extensions with dots
                for ext in ext_list:
                    f.write(f".{ext}\n")
            
            # Modify command to use extension fuzzing
            fuzz_url_with_ext = f"{target_url}FUZZFUZ2Z"
            cmd_parts = [
                "ffuf",
                "-w", f"{wordlist}:FUZZ",
                "-w", f"{ext_file}:FUZ2Z", 
                "-u", fuzz_url_with_ext,
                "-t", str(threads),
                "-timeout", str(timeout),
                "-mc", match_codes,
                "-o", output_file,
                "-of", "json",
                "-s"
            ]
    
    # Add rate limiting if specified
    if rate_limit > 0:
        cmd_parts.extend(["-rate", str(rate_limit)])
    
    # Add filters if configured
    ffuf_config = web_config.ffuf
    if ffuf_config.get("filter_size"):
        cmd_parts.extend(["-fs", ffuf_config["filter_size"]])
    if ffuf_config.get("filter_words"):
        cmd_parts.extend(["-fw", ffuf_config["filter_words"]])
    
    # Add custom headers if configured
    headers = ffuf_config.get("headers", {})
    for header, value in headers.items():
        cmd_parts.extend(["-H", f"{header}: {value}"])
    
    console.print(f"[dim]Command: {' '.join(cmd_parts)}[/dim]")
    
    try:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console
        ) as progress:
            task = progress.add_task("Running ffuf...", total=None)
            
            # Run ffuf
            result = subprocess.run(
                cmd_parts,
                capture_output=True,
                text=True,
                timeout=timeout * 10  # Give ffuf plenty of time
            )
            
            progress.update(task, description="ffuf completed!")
        
        # Check if ffuf succeeded
        if result.returncode != 0:
            console.print(f"[red]ffuf failed with return code {result.returncode}[/red]")
            if result.stderr:
                console.print(f"[red]Error: {result.stderr}[/red]")
            return None
        
        # Parse JSON output
        if not os.path.exists(output_file):
            console.print("[yellow]ffuf completed but no output file found[/yellow]")
            return None
        
        with open(output_file, 'r') as f:
            ffuf_data = json.load(f)
        
        # Extract results
        results = ffuf_data.get("results", [])
        
        # Process and enhance results
        processed_results = []
        for item in results:
            processed_item = {
                "url": item.get("url", ""),
                "status": item.get("status", 0),
                "length": item.get("length", 0),
                "words": item.get("words", 0),
                "lines": item.get("lines", 0),
                "redirectlocation": item.get("redirectlocation", ""),
                "input": item.get("input", {})
            }
            processed_results.append(processed_item)
        
        # Sort by status code and URL
        processed_results.sort(key=lambda x: (x["status"], x["url"]))
        
        # Create final data structure
        final_data = {
            "target": target,
            "target_url": target_url,
            "scan_timestamp": datetime.utcnow().isoformat() + "Z",
            "results": processed_results,
            "total_results": len(processed_results),
            "config_used": {
                "wordlist": wordlist,
                "extensions": extensions,
                "threads": threads,
                "timeout": timeout,
                "match_codes": match_codes,
                "rate_limit": rate_limit
            },
            "ffuf_version": get_ffuf_version()
        }
        
        # Display results
        print_ffuf_table(final_data, target)
        
        # Save reports
        report.save_report(final_data, target, "web_recon")
        report.save_report_html(final_data, target, "web_recon")
        
        # Save raw ffuf output
        with open(output_file, 'r') as f:
            raw_data = f.read()
        report.save_raw(target, "web_recon", raw_data, "json")
        
        # Cleanup temporary files
        try:
            os.remove(output_file)
            if extensions and os.path.exists(f"/tmp/extensions_{timestamp}.txt"):
                os.remove(f"/tmp/extensions_{timestamp}.txt")
        except:
            pass
        
        console.print("[green]Web reconnaissance completed successfully[/green]")
        return final_data
        
    except subprocess.TimeoutExpired:
        console.print("[red]ffuf timed out[/red]")
        return None
    except Exception as e:
        console.print(f"[red]ffuf execution failed: {e}[/red]")
        return None

def get_ffuf_version() -> str:
    """Get ffuf version"""
    try:
        result = subprocess.run(["ffuf", "-V"], capture_output=True, text=True)
        if result.returncode == 0:
            return result.stdout.strip()
    except:
        pass
    return "unknown"

def print_ffuf_table(data: dict, target: str):
    """Pretty-print results of ffuf scan in a Rich table."""
    if not data or "results" not in data or not data.get("results"):
        console.print("[yellow]No results found.[/yellow]")
        return

    results = data.get("results", [])
    
    table = Table(title=f"Web Recon Results - {target}")
    table.add_column("URL", style="cyan", overflow="fold")
    table.add_column("Status", style="green", justify="center")
    table.add_column("Length", justify="right")
    table.add_column("Words", justify="right")
    table.add_column("Lines", justify="right")

    # Show results (limit to first 20 for readability)
    display_count = min(len(results), 20)
    for item in results[:display_count]:
        status_code = item.get("status", "-")
        
        # Color code status
        if str(status_code).startswith("2"):
            status_style = "green"
        elif str(status_code).startswith("3"):
            status_style = "yellow"
        elif str(status_code).startswith("4"):
            status_style = "red"
        elif str(status_code).startswith("5"):
            status_style = "red bold"
        else:
            status_style = "white"
        
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
    
    # Show status code breakdown
    status_counts = {}
    for item in results:
        status = str(item.get("status", "unknown"))
        status_counts[status] = status_counts.get(status, 0) + 1
    
    if status_counts:
        console.print("\n[bold]Status Code Summary:[/bold]")
        for status, count in sorted(status_counts.items()):
            console.print(f"  • {status}: {count}")
    
    # Show config info used
    config_used = data.get("config_used", {})
    if config_used:
        console.print(f"\n[dim]Wordlist: {os.path.basename(config_used.get('wordlist', 'N/A'))}[/dim]")
        console.print(f"[dim]Threads: {config_used.get('threads', 'N/A')}, Timeout: {config_used.get('timeout', 'N/A')}s[/dim]")

# Main function for standalone testing
if __name__ == "__main__":
    target_host = input("Enter target URL (e.g., https://example.com): ").strip()
    run_ffuf(target_host)