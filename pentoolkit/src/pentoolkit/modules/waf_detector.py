# pentoolkit/modules/waf_detector.py
import subprocess
import shlex
import json
import datetime
from typing import Dict, Optional, Any

import requests
from requests.exceptions import RequestException
from rich.console import Console
from rich.table import Table

from pentoolkit.utils import report

console = Console()

# Minimal known WAF header/body signatures (non-exhaustive)
WAF_SIGNATURES = {
    "cloudflare": {
        "headers": ["cf-ray", "server: cloudflare"],
        "server_tokens": ["cloudflare"]
    },
    "akamai": {
        "headers": ["server: akamaigHost".lower()],
        "server_tokens": ["akamai"]
    },
    "sucuri": {
        "headers": ["x-sucuri-id", "x-sucuri-cache"],
        "server_tokens": ["sucuri"]
    },
    "barracuda": {
        "headers": ["server: barracuda"],
        "server_tokens": ["barracuda"]
    },
    "aws_waf": {
        "headers": ["x-amzn-requestid", "x-amz-cf-id"],
        "body": ["AWS WAF", "Request blocked by AWS WAF"]
    },
    "f5_bigip": {
        "headers": ["x-cdn", "x-bigip-server"],
        "server_tokens": ["bigip"]
    },
    "fastly": {
        "headers": ["x-fastly-request-id"],
        "server_tokens": ["fastly"]
    },
    "mod_security": {
        "headers": ["x-mod-pagespeed"],
        "body": ["Mod_Security", "mod_security"]
    },
    # Add more heuristics as you see fit
}


def _try_wafw00f(target: str, timeout: int = 60) -> Optional[str]:
    """
    Try to call wafw00f CLI (if installed) to fingerprint the target.
    Returns raw wafw00f output (text) or None if wafw00f is not available/fails.
    """
    cmd = f"wafw00f {shlex.quote(target)}"
    try:
        completed = subprocess.run(
            shlex.split(cmd),
            capture_output=True,
            text=True,
            timeout=timeout
        )
        # wafw00f outputs textual fingerprint which we capture
        if completed.returncode == 0 and completed.stdout:
            return completed.stdout
        # Even non-zero may include useful output
        if completed.stdout:
            return completed.stdout
    except FileNotFoundError:
        # wafw00f not installed
        return None
    except Exception as e:
        console.print(f"[!] wafw00f invocation failed: {e}", style="yellow")
        return None
    return None


def _http_probe(target: str, use_https: bool = False, timeout: int = 10) -> Optional[Dict[str, Any]]:
    """
    Make a single HTTP(S) request to the target and return headers & snippet.
    target may be a hostname or host:port
    """
    scheme = "https" if use_https else "http"
    url = f"{scheme}://{target}"
    try:
        resp = requests.get(url, timeout=timeout, allow_redirects=True, verify=False)
        return {
            "url": url,
            "status_code": resp.status_code,
            "headers": {k.lower(): v for k, v in resp.headers.items()},
            "body_snippet": (resp.text[:4000] if resp.text else "")
        }
    except RequestException as e:
        # Could not reach; return None
        return None


def _heuristic_detect(probe: Dict[str, Any]) -> Dict[str, Any]:
    """
    Simple heuristics: check headers and body snippet against known signatures.
    Returns a dict with detected flag, matches list and best_guess product.
    """
    detected = False
    matches = []
    best_guess = None

    headers = probe.get("headers", {})
    body = probe.get("body_snippet", "").lower()

    # server header token checks
    server_header = headers.get("server", "").lower()
    combined_header_str = " ".join([f"{k}: {v}" for k, v in headers.items()]).lower()

    for product, sig in WAF_SIGNATURES.items():
        found = False
        # header keywords
        for h in sig.get("headers", []):
            if h.lower() in combined_header_str:
                matches.append(f"header:{product}:{h}")
                found = True
        # server tokens
        for tok in sig.get("server_tokens", []):
            if tok.lower() in server_header:
                matches.append(f"server-token:{product}:{tok}")
                found = True
        # body patterns
        for pat in sig.get("body", []):
            if pat.lower() in body:
                matches.append(f"body:{product}:{pat}")
                found = True

        if found and not best_guess:
            best_guess = product
            detected = True

    # additional generic checks
    if not detected:
        # some WAFs set X-Frame-Options, X-Content-Type-Options etc — not definitive but helpful
        if any(k for k in headers.keys() if k.startswith("x-")):
            # low-confidence heuristic
            matches.append("headers:x-headers-present")
    return {"detected": detected, "best_guess": best_guess, "matches": matches}


def detect(target: str) -> Dict:
    """
    Main entry: detect WAF for a target.
    Returns a normalized dict and saves reports (JSON + HTML + raw).
    """
    console.print(f"[WAF] Detecting WAF on: {target}")

    result = {
        "target": target,
        "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
        "waf": {
            "detected": False,
            "product": None,
            "confidence": "low",
            "matches": [],
            "details": {},
            "raw": None
        }
    }

    # 1) Try wafw00f if installed (best-fidelity)
    wafw00f_out = _try_wafw00f(target)
    if wafw00f_out:
        result["waf"]["raw"] = wafw00f_out
        # Save raw output
        try:
            report.save_raw(target, "waf", wafw00f_out, ext="txt")
        except Exception:
            pass

        # Quick parse of wafw00f textual output for product
        # wafw00f often includes lines like: "Detected WAF: Cloudflare"
        lines = [l.strip() for l in wafw00f_out.splitlines() if l.strip()]
        found_prod = None
        for ln in lines:
            low = ln.lower()
            if "detected" in low and ":" in ln:
                parts = ln.split(":", 1)
                if len(parts) > 1:
                    found_prod = parts[1].strip()
                    break
            # fallback: look for known product names
            for prod in WAF_SIGNATURES.keys():
                if prod in low:
                    found_prod = prod
                    break
            if found_prod:
                break

        result["waf"].update({
            "detected": True if found_prod else True,
            "product": found_prod or "unknown",
            "confidence": "high",
            "details": {"wafw00f_summary": wafw00f_out.splitlines()[:20]}
        })
        # Save structured JSON + HTML
        try:
            report.save_report(result, target, "waf")
            report.save_report_html(result["waf"], target, "waf")
        except Exception as e:
            console.print(f"[!] Failed to save WAF report: {e}", style="yellow")
        # Pretty print
        try:
            tbl = Table(title=f"WAF Detection - {target}")
            tbl.add_column("Field", style="bold")
            tbl.add_column("Value")
            tbl.add_row("Detected", str(result["waf"]["detected"]))
            tbl.add_row("Product", str(result["waf"]["product"]))
            tbl.add_row("Confidence", result["waf"]["confidence"])
            tbl.add_row("Matches", ", ".join(result["waf"]["matches"] or []) or "-")
            console.print(tbl)
        except Exception:
            pass
        return result

    # 2) Lightweight HTTP heuristic probe (try HTTPS first, then HTTP)
    probe = _http_probe(target, use_https=True)
    if not probe:
        probe = _http_probe(target, use_https=False)

    if not probe:
        # unreachable
        result["waf"]["details"]["error"] = "Target unreachable via HTTP/HTTPS"
        result["waf"]["confidence"] = "none"
        # Save and return
        report.save_report(result, target, "waf")
        report.save_report_html(result["waf"], target, "waf")
        console.print(f"[WAF] Could not reach {target} via HTTP/HTTPS", style="yellow")
        return result

    # Heuristic detection
    heur = _heuristic_detect(probe)
    result["waf"]["detected"] = heur["detected"]
    result["waf"]["product"] = heur["best_guess"]
    result["waf"]["matches"] = heur["matches"]
    result["waf"]["details"]["probe"] = probe
    result["waf"]["confidence"] = "medium" if heur["detected"] else "low"

    # Small body-snippet check for common block strings
    snippet = probe.get("body_snippet", "").lower()
    if "access denied" in snippet or "forbidden" in snippet or "request blocked" in snippet:
        result["waf"]["detected"] = True
        if not result["waf"]["product"]:
            result["waf"]["product"] = "unknown"
        result["waf"]["confidence"] = "medium"
        result["waf"]["matches"].append("body:blocking-pattern")

    # Save raw probe as text for debugging
    try:
        raw_probe_text = json.dumps(probe, indent=2, default=str)
        report.save_raw(target, "waf", raw_probe_text, ext="txt")
        result["waf"]["raw"] = raw_probe_text
    except Exception:
        pass

    # Save structured JSON + HTML
    try:
        report.save_report(result, target, "waf")
        report.save_report_html(result["waf"], target, "waf")
    except Exception as e:
        console.print(f"[!] Failed to save WAF report: {e}", style="yellow")

    # Pretty print summary
    try:
        tbl = Table(title=f"WAF Detection - {target}")
        tbl.add_column("Field", style="bold")
        tbl.add_column("Value")
        tbl.add_row("Detected", str(result["waf"]["detected"]))
        tbl.add_row("Product", str(result["waf"]["product"] or "-"))
        tbl.add_row("Confidence", result["waf"]["confidence"])
        tbl.add_row("Matches", ", ".join(result["waf"]["matches"] or []) or "-")
        tbl.add_row("Probe URL", probe.get("url", "-"))
        tbl.add_row("Status Code", str(probe.get("status_code", "-")))
        console.print(tbl)
    except Exception:
        pass

    return result
