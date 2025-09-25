# pentoolkit/main.py
from pentoolkit.modules import nmap_scanner, ssl_scanner, whois_lookup, waf_detector, web_recon

def run_scan(target: str, modules: str = "all", scan_type: str = "default", nse: str = None, extra_args: str = ""):
    """
    Orchestrates all scans for a target. Returns a dictionary with results for each module.
    """
    selected_modules = modules.split(",") if modules != "all" else ["nmap", "ssl", "whois", "waf", "web_recon"]
    results_summary = {}

    if "nmap" in selected_modules:
        print(f"[NMAP] Running scan on {target}")
        nmap_result = nmap_scanner.scan(target, scan_type, nse, extra_args)
        results_summary["nmap"] = nmap_result

    if "ssl" in selected_modules:
        print(f"[SSL] Running scan on {target}")
        ssl_result = ssl_scanner.scan(target)
        results_summary["ssl"] = ssl_result

    if "whois" in selected_modules:
        print(f"[WHOIS] Running lookup on {target}")
        whois_result = whois_lookup.lookup(target)
        results_summary["whois"] = whois_result

    if "waf" in selected_modules:
        print(f"[WAF] Running detection on {target}")
        waf_result = waf_detector.detect(target)
        results_summary["waf"] = waf_result

    if "web_recon" in selected_modules:
        print(f"[WEB_RECON] Running web recon on {target}")
        web_result = web_recon.run_ffuf(target)
        results_summary["web_recon"] = web_result

    print("[+] Scan completed.\n")
    return results_summary
