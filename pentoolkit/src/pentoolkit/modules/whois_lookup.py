# pentoolkit/modules/whois_lookup.py
import subprocess
import shlex
import datetime
import ipaddress
from typing import Dict, Optional

from pentoolkit.utils import report
from rich.console import Console
from rich.table import Table

console = Console()


def _is_ip(target: str) -> bool:
    try:
        ipaddress.ip_address(target)
        return True
    except ValueError:
        return False


def _run_system_whois(target: str, timeout: int = 20) -> Optional[str]:
    """Run system whois and return raw text."""
    cmd = f"whois {shlex.quote(target)}"
    try:
        proc = subprocess.run(
            shlex.split(cmd),
            capture_output=True,
            text=True,
            timeout=timeout
        )
        if proc.returncode == 0 or proc.stdout:
            return proc.stdout
    except Exception as e:
        console.print(f"[!] system whois failed: {e}", style="yellow")
    return None


def _parse_ip_whois(raw: str) -> Dict:
    """Parse key RIR WHOIS fields from raw text."""
    parsed = {}
    for line in raw.splitlines():
        line = line.strip()
        if not line or ":" not in line:
            continue
        key, val = line.split(":", 1)
        key = key.strip().lower()
        val = val.strip()

        if key in ["netrange", "inetnum"]:
            parsed["range"] = val
        elif key in ["cidr"]:
            parsed["cidr"] = val
        elif key in ["country"]:
            parsed["country"] = val
        elif key in ["orgname", "descr", "organization"]:
            parsed.setdefault("org", val)
        elif "abuse" in key and "email" in key:
            parsed["abuse_email"] = val
        elif key in ["admin-c", "tech-c"]:
            parsed.setdefault("contacts", []).append(f"{key.upper()}: {val}")

    return parsed


def _parse_domain_whois(raw: str) -> Dict:
    """Basic parsing for domain WHOIS if python-whois is missing."""
    parsed = {}
    for line in raw.splitlines():
        lower = line.lower()
        if "registrar" in lower and "registrar url" not in lower and ":" in line:
            parsed.setdefault("registrar", line.split(":", 1)[1].strip())
        elif "creation date" in lower or "created on" in lower:
            parsed.setdefault("creation_date", line.split(":", 1)[1].strip())
        elif "expiry date" in lower or "expiration date" in lower or "expires on" in lower:
            parsed.setdefault("expiration_date", line.split(":", 1)[1].strip())
        elif "name server" in lower or lower.startswith("nserver"):
            parsed.setdefault("name_servers", []).append(line.split()[-1].strip())
    return parsed


def _attempt_python_whois(target: str) -> Optional[Dict]:
    """Try python-whois for domains only."""
    try:
        import whois as pywhois
    except ImportError:
        return None

    try:
        res = pywhois.whois(target)
        return dict(res)
    except Exception as e:
        console.print(f"[!] python-whois failed: {e}", style="yellow")
        return None


def lookup(target: str) -> Dict:
    """WHOIS lookup for domain or IP."""
    console.print(f"[WHOIS] Looking up: {target}")
    result = {
        "target": target,
        "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
        "whois": {}
    }

    raw_text = _run_system_whois(target)

    if _is_ip(target):
        # IP WHOIS (RIR parsing)
        if raw_text:
            parsed = _parse_ip_whois(raw_text)
            result["whois"].update(parsed)
    else:
        # Domain WHOIS
        py_data = _attempt_python_whois(target)
        if py_data:
            result["whois"].update(py_data)
        elif raw_text:
            parsed = _parse_domain_whois(raw_text)
            result["whois"].update(parsed)

    # Always store raw
    if raw_text:
        result["whois"]["raw_text"] = raw_text
        report.save_raw(target, "whois", raw_text, ext="txt")

    # Save JSON + HTML reports
    report.save_report(result, target, "whois")
    report.save_report_html(result["whois"], target, "whois")

    # Pretty print
    tbl = Table(title=f"WHOIS - {target}")
    tbl.add_column("Field", style="bold")
    tbl.add_column("Value")
    for k, v in result["whois"].items():
        if k == "raw_text":
            continue
        val = ", ".join(v) if isinstance(v, list) else str(v)
        tbl.add_row(k, val)
    console.print(tbl)

    return result
