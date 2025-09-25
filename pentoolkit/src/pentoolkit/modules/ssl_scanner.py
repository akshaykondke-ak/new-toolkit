# pentoolkit/modules/ssl_scanner.py
import socket
import ssl
import re
from datetime import datetime
from pentoolkit.utils import report
from pentoolkit.utils.config import get_config
from rich.console import Console
from rich.table import Table
from typing import Dict, List, Optional, Tuple

console = Console()

# Comprehensive cipher suite security classifications
WEAK_CIPHERS = {
    'NULL': 'Critical - No encryption',
    'RC4': 'Critical - Broken stream cipher',
    'DES': 'Critical - Weak encryption (56-bit)',
    '3DES': 'High - Triple DES deprecated',
    'MD5': 'Critical - Broken hash function',
    'SHA1': 'Medium - SHA-1 deprecated for signatures',
    'EXPORT': 'Critical - Export-grade encryption',
    'ANON': 'Critical - Anonymous key exchange'
}

DEPRECATED_TLS_VERSIONS = {
    'SSLv2': 'Critical - SSL 2.0 deprecated',
    'SSLv3': 'Critical - SSL 3.0 deprecated', 
    'TLSv1': 'High - TLS 1.0 deprecated',
    'TLSv1.1': 'Medium - TLS 1.1 deprecated'
}

def analyze_cipher_security(cipher_info: tuple, tls_version: str = None) -> Dict:
    """Analyze cipher suite for security issues."""
    if not cipher_info or len(cipher_info) < 1:
        return {
            'security_level': 'Unknown',
            'issues': ['Unable to analyze cipher suite'],
            'score': 0
        }
    
    cipher_name = cipher_info[0].upper() if cipher_info[0] else 'UNKNOWN'
    protocol = cipher_info[1] if len(cipher_info) > 1 else ''
    strength = cipher_info[2] if len(cipher_info) > 2 else 0
    
    issues = []
    security_level = 'Good'
    score = 100
    
    # Check for weak ciphers
    for weak_cipher, description in WEAK_CIPHERS.items():
        if weak_cipher in cipher_name:
            issues.append(f"{weak_cipher}: {description}")
            if weak_cipher in ['NULL', 'RC4', 'DES', 'EXPORT', 'ANON']:
                security_level = 'Critical'
                score = min(score, 20)
            elif weak_cipher in ['3DES', 'MD5']:
                security_level = 'High Risk' if security_level != 'Critical' else security_level
                score = min(score, 40)
            else:
                security_level = 'Medium Risk' if security_level not in ['Critical', 'High Risk'] else security_level
                score = min(score, 60)
    
    # Check key strength
    if strength and strength < 128:
        issues.append(f"Weak key strength: {strength} bits")
        security_level = 'Critical'
        score = min(score, 20)
    elif strength and strength < 256:
        issues.append(f"Moderate key strength: {strength} bits")
        score = min(score, 80)
    
    # Check for forward secrecy - improved logic for TLS 1.3
    has_forward_secrecy = False
    
    if tls_version == 'TLSv1.3':
        # All TLS 1.3 cipher suites provide perfect forward secrecy by design
        has_forward_secrecy = True
    elif any(fs in cipher_name for fs in ['DHE', 'ECDHE']):
        # Traditional forward secrecy indicators
        has_forward_secrecy = True
    elif 'TLS_AES_' in cipher_name or 'TLS_CHACHA20_' in cipher_name:
        # TLS 1.3 cipher suite patterns
        has_forward_secrecy = True
    
    if not has_forward_secrecy:
        issues.append("No Perfect Forward Secrecy")
        score = min(score, 70)
    
    # Additional cipher analysis
    if 'CBC' in cipher_name and tls_version != 'TLSv1.3':
        issues.append("CBC mode cipher - potential padding oracle attacks")
        score = min(score, 85)
    
    # Bonus points for strong modern ciphers
    if any(modern in cipher_name for modern in ['GCM', 'CHACHA20', 'POLY1305']):
        # These are good AEAD ciphers
        pass
    
    return {
        'security_level': security_level,
        'issues': issues,
        'score': score,
        'cipher_name': cipher_name,
        'key_strength': strength,
        'has_forward_secrecy': has_forward_secrecy
    }

def analyze_tls_version_security(tls_version: str) -> Dict:
    """Analyze TLS version for security issues."""
    issues = []
    security_level = 'Good'
    score = 100
    
    if not tls_version:
        issues.append("TLS version unknown")
        return {'security_level': 'Warning', 'issues': issues, 'score': 60}
    
    # Check for deprecated versions - be more specific to avoid false positives
    if tls_version == 'SSLv2':
        issues.append("SSLv2: Critical - SSL 2.0 deprecated")
        security_level = 'Critical'
        score = 20
    elif tls_version == 'SSLv3':
        issues.append("SSLv3: Critical - SSL 3.0 deprecated")
        security_level = 'Critical'
        score = 20
    elif tls_version == 'TLSv1.0' or tls_version == 'TLSv1':
        issues.append("TLS 1.0: High - TLS 1.0 deprecated")
        security_level = 'High Risk'
        score = 40
    elif tls_version == 'TLSv1.1':
        issues.append("TLS 1.1: Medium - TLS 1.1 deprecated")
        security_level = 'Medium Risk'
        score = 60
    elif tls_version == 'TLSv1.2':
        # TLS 1.2 is acceptable but not the latest
        score = 85
    elif tls_version == 'TLSv1.3':
        # TLS 1.3 is the most secure - perfect score
        score = 100
    
    return {
        'security_level': security_level,
        'issues': issues,
        'score': score
    }

def get_certificate_chain_length(ssl_socket) -> int:
    """Safely get certificate chain length with fallbacks."""
    try:
        # Method 1: Try getpeercert_chain if available (Python 3.10+)
        if hasattr(ssl_socket, 'getpeercert_chain'):
            cert_chain = ssl_socket.getpeercert_chain()
            return len(cert_chain) if cert_chain else 1
    except Exception:
        pass
    
    try:
        # Method 2: Use OpenSSL if available
        import OpenSSL.crypto
        cert_der = ssl_socket.getpeercert(binary_form=True)
        cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_ASN1, cert_der)
        # This is a simplified approach - actual chain analysis would be more complex
        return 1  # Single certificate detected
    except (ImportError, Exception):
        pass
    
    # Method 3: Fallback to 1 (we know at least the peer cert exists)
    return 1

def extract_certificate_extensions(cert: Dict) -> Dict:
    """Extract and analyze certificate extensions."""
    extensions = {
        'san': [],
        'key_usage': [],
        'extended_key_usage': [],
        'basic_constraints': {},
        'crl_distribution_points': [],
        'authority_info_access': []
    }
    
    # Subject Alternative Names
    if 'subjectAltName' in cert:
        extensions['san'] = [alt[1] for alt in cert['subjectAltName']]
    
    # Other extensions would require more detailed certificate parsing
    # This is a basic implementation
    
    return extensions

def check_certificate_validity(cert: Dict, ssl_config) -> Dict:
    """Check certificate validity and generate warnings."""
    validity_info = {
        'is_valid': True,
        'issues': [],
        'days_until_expiry': None,
        'warning_level': 'None'
    }
    
    try:
        not_after = cert.get('notAfter')
        not_before = cert.get('notBefore')
        
        if not_after:
            try:
                expiry_dt = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                now = datetime.utcnow()
                days_left = (expiry_dt - now).days
                
                validity_info['days_until_expiry'] = days_left
                
                if days_left < 0:
                    validity_info['is_valid'] = False
                    validity_info['issues'].append(f"Certificate expired {abs(days_left)} days ago")
                    validity_info['warning_level'] = 'Critical'
                elif days_left <= ssl_config.expiry_warning["critical"]:
                    validity_info['issues'].append(f"Certificate expires in {days_left} days")
                    validity_info['warning_level'] = 'Critical'
                elif days_left <= ssl_config.expiry_warning["warning"]:
                    validity_info['issues'].append(f"Certificate expires in {days_left} days")
                    validity_info['warning_level'] = 'Warning'
            except (ValueError, TypeError) as e:
                validity_info['issues'].append(f"Unable to parse certificate expiry date: {not_after}")
                validity_info['warning_level'] = 'Warning'
        else:
            validity_info['issues'].append("Certificate expiry date not available")
            validity_info['warning_level'] = 'Warning'
        
        if not_before:
            try:
                start_dt = datetime.strptime(not_before, "%b %d %H:%M:%S %Y %Z")
                if start_dt > datetime.utcnow():
                    validity_info['is_valid'] = False
                    validity_info['issues'].append("Certificate is not yet valid")
                    validity_info['warning_level'] = 'Critical'
            except (ValueError, TypeError):
                pass  # Ignore parsing errors for start date
    
    except Exception as e:
        validity_info['issues'].append(f"Error analyzing certificate validity: {e}")
        validity_info['warning_level'] = 'Warning'
    
    return validity_info

def print_ssl_table(results: dict, config):
    """Print SSL info in a Rich table with comprehensive security analysis."""
    ssl_config = config.ssl_config
    
    table = Table(title=f"SSL Certificate Analysis - {results.get('target')}:{results.get('port', 443)}")
    table.add_column("Field", style="bold cyan", width=25)
    table.add_column("Value", style="white", width=50)
    table.add_column("Security", style="white", width=20)

    # Basic SSL information
    table.add_row("SSL Version", results.get("ssl_version", "-"), 
                  results.get("tls_security", {}).get("security_level", "-"))
    
    # Cipher suite with security analysis
    cipher_suite = results.get("cipher_suite", "-")
    cipher_security = results.get("cipher_security", {})
    security_level = cipher_security.get("security_level", "Unknown")
    
    if security_level == "Critical":
        security_color = "[red bold]Critical[/red bold]"
    elif security_level == "High Risk":
        security_color = "[red]High Risk[/red]"
    elif security_level == "Medium Risk":
        security_color = "[yellow]Medium Risk[/yellow]"
    else:
        security_color = "[green]Good[/green]"
    
    table.add_row("Cipher Suite", cipher_suite, security_color)
    table.add_row("Key Strength", f"{cipher_security.get('key_strength', 'Unknown')} bits", "")
    
    # Weak ciphers checked
    weak_ciphers_checked = ", ".join(WEAK_CIPHERS.keys())
    weak_ciphers_found = cipher_security.get("issues", [])
    weak_ciphers_status = "None detected" if not weak_ciphers_found else ", ".join(weak_ciphers_found)
    table.add_row("Weak Ciphers Checked", weak_ciphers_checked, weak_ciphers_status)
    
    # Certificate information
    subject = results.get("subject", {})
    subject_str = ", ".join([f"{k}={v}" for k, v in subject.items()]) if subject else "-"
    table.add_row("Subject", subject_str, "")
    
    issuer = results.get("issuer", {})
    issuer_str = ", ".join([f"{k}={v}" for k, v in issuer.items()]) if issuer else "-"
    table.add_row("Issuer", issuer_str, "")

    # Certificate validity with color coding
    validity = results.get("certificate_validity", {})
    valid_until = results.get("valid_until") or "-"  # Handle None case
    warning_level = validity.get("warning_level", "None")
    
    if warning_level == "Critical":
        validity_color = f"[red bold]{valid_until}[/red bold]"
    elif warning_level == "Warning":
        validity_color = f"[yellow]{valid_until}[/yellow]"
    else:
        validity_color = f"[green]{valid_until}[/green]"
    
    table.add_row("Valid Until", validity_color, warning_level)
    table.add_row("Valid From", results.get("valid_from", "-"), "")
    
    # Additional security information
    table.add_row("Chain Length", str(results.get("cert_chain_length", "Unknown")), "")
    
    # Subject Alternative Names
    san_list = results.get("certificate_extensions", {}).get("san", [])
    san_str = ", ".join(san_list[:3])  # Show first 3 SANs
    if len(san_list) > 3:
        san_str += f" (and {len(san_list) - 3} more)"
    table.add_row("Subject Alt Names", san_str or "-", "")

    console.print(table)
    
    # Print security issues if any
    all_issues = []
    all_issues.extend(cipher_security.get("issues", []))
    all_issues.extend(results.get("tls_security", {}).get("issues", []))
    all_issues.extend(validity.get("issues", []))
    
    if all_issues:
        console.print("\n[bold red]Security Issues Found:[/bold red]")
        for issue in all_issues:
            console.print(f"  [red]•[/red] {issue}")
    
    # Print security score
    total_score = (
        cipher_security.get("score", 100) + 
        results.get("tls_security", {}).get("score", 100) + 
        (0 if validity.get("warning_level") == "Critical" else 100 if validity.get("warning_level") == "None" else 50)
    ) // 3
    
    if total_score >= 80:
        score_color = "[green]"
    elif total_score >= 60:
        score_color = "[yellow]"
    else:
        score_color = "[red]"
    
    console.print(f"\n[bold]Security Score:[/bold] {score_color}{total_score}/100[/{score_color[1:-1]}]")

def extract_certificate_comprehensive(ssock, target: str) -> Dict:
    """Extract certificate information using multiple methods for robustness."""
    cert_info = {
        'subject': {},
        'issuer': {},
        'not_before': None,
        'not_after': None,
        'serial_number': None,
        'signature_algorithm': None,
        'san_list': [],
        'version': None,
        'raw_cert': None
    }
    
    try:
        # Method 1: Standard getpeercert
        cert = ssock.getpeercert()
        if cert:
            console.print("[dim]Method 1: Standard certificate extraction successful[/dim]")
            
            # Parse subject
            if 'subject' in cert and cert['subject']:
                try:
                    # Handle the nested tuple format: ((('CN', 'google.com'),), (('O', 'Organization'),))
                    subject_dict = {}
                    for rdn in cert['subject']:  # RDN = Relative Distinguished Name
                        for name_attr in rdn:
                            if len(name_attr) >= 2:
                                subject_dict[name_attr[0]] = name_attr[1]
                    cert_info['subject'] = subject_dict
                except Exception as e:
                    console.print(f"[yellow]Subject parsing error: {e}[/yellow]")
            
            # Parse issuer 
            if 'issuer' in cert and cert['issuer']:
                try:
                    issuer_dict = {}
                    for rdn in cert['issuer']:
                        for name_attr in rdn:
                            if len(name_attr) >= 2:
                                issuer_dict[name_attr[0]] = name_attr[1]
                    cert_info['issuer'] = issuer_dict
                except Exception as e:
                    console.print(f"[yellow]Issuer parsing error: {e}[/yellow]")
            
            # Extract other fields
            cert_info['not_before'] = cert.get('notBefore')
            cert_info['not_after'] = cert.get('notAfter')
            cert_info['serial_number'] = cert.get('serialNumber')
            cert_info['signature_algorithm'] = cert.get('signatureAlgorithm')
            cert_info['version'] = cert.get('version')
            
            # Extract Subject Alternative Names
            if 'subjectAltName' in cert:
                cert_info['san_list'] = [name[1] for name in cert['subjectAltName']]
        
        else:
            console.print("[yellow]Method 1: No certificate data from getpeercert()[/yellow]")
    
    except Exception as e:
        console.print(f"[yellow]Method 1 failed: {e}[/yellow]")
    
    # Method 2: Binary certificate extraction and parsing
    if not cert_info['subject'] or not cert_info['not_after']:
        try:
            console.print("[dim]Attempting Method 2: Binary certificate extraction[/dim]")
            cert_der = ssock.getpeercert(binary_form=True)
            if cert_der:
                # Try to parse with cryptography library if available
                try:
                    from cryptography import x509
                    from cryptography.hazmat.backends import default_backend
                    
                    cert_obj = x509.load_der_x509_certificate(cert_der, default_backend())
                    
                    # Extract subject
                    subject_dict = {}
                    for attribute in cert_obj.subject:
                        subject_dict[attribute.oid._name] = attribute.value
                    if subject_dict:
                        cert_info['subject'] = subject_dict
                    
                    # Extract issuer
                    issuer_dict = {}
                    for attribute in cert_obj.issuer:
                        issuer_dict[attribute.oid._name] = attribute.value
                    if issuer_dict:
                        cert_info['issuer'] = issuer_dict
                    
                    # Extract dates
                    cert_info['not_before'] = cert_obj.not_valid_before_utc.strftime("%b %d %H:%M:%S %Y GMT")
                    cert_info['not_after'] = cert_obj.not_valid_after_utc.strftime("%b %d %H:%M:%S %Y GMT")
                    
                    # Extract serial number
                    cert_info['serial_number'] = str(cert_obj.serial_number)
                    
                    # Extract SAN
                    try:
                        san_ext = cert_obj.extensions.get_extension_for_oid(x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
                        cert_info['san_list'] = [name.value for name in san_ext.value]
                    except:
                        pass
                    
                    console.print("[green]Method 2: Cryptography library extraction successful[/green]")
                    
                except ImportError:
                    console.print("[yellow]Cryptography library not available for enhanced parsing[/yellow]")
                    console.print("[cyan]Install with: pip install cryptography[/cyan]")
                except Exception as e:
                    console.print(f"[yellow]Method 2 cryptography parsing failed: {e}[/yellow]")
        
        except Exception as e:
            console.print(f"[yellow]Method 2 failed: {e}[/yellow]")
    
    # Method 3: OpenSSL fallback if available
    if not cert_info['subject'] or not cert_info['not_after']:
        try:
            console.print("[dim]Attempting Method 3: OpenSSL parsing[/dim]")
            import subprocess
            import tempfile
            
            cert_der = ssock.getpeercert(binary_form=True)
            if cert_der:
                with tempfile.NamedTemporaryFile(mode='wb', delete=False) as tmp:
                    tmp.write(cert_der)
                    tmp_path = tmp.name
                
                try:
                    # Use OpenSSL command to extract certificate info
                    result = subprocess.run(
                        ['openssl', 'x509', '-in', tmp_path, '-inform', 'DER', '-text', '-noout'],
                        capture_output=True, text=True, timeout=10
                    )
                    
                    if result.returncode == 0:
                        # Parse OpenSSL output
                        openssl_output = result.stdout
                        
                        # Extract subject line
                        for line in openssl_output.split('\n'):
                            line = line.strip()
                            if line.startswith('Subject:'):
                                # Parse subject from OpenSSL format
                                subject_str = line.replace('Subject:', '').strip()
                                # Simple parsing - could be enhanced
                                if 'CN=' in subject_str and not cert_info['subject']:
                                    cert_info['subject'] = {'CN': 'Extracted via OpenSSL'}
                            
                            elif line.startswith('Not After :'):
                                if not cert_info['not_after']:
                                    cert_info['not_after'] = line.replace('Not After :', '').strip()
                        
                        console.print("[green]Method 3: OpenSSL extraction successful[/green]")
                
                finally:
                    import os
                    os.unlink(tmp_path)
        
        except Exception as e:
            console.print(f"[yellow]Method 3 failed: {e}[/yellow]")
    
    # Debug output
    console.print(f"[dim]Final certificate extraction results:[/dim]")
    console.print(f"[dim]  Subject: {cert_info['subject']}[/dim]")
    console.print(f"[dim]  Issuer: {cert_info['issuer']}[/dim]")
    console.print(f"[dim]  Valid until: {cert_info['not_after']}[/dim]")
    console.print(f"[dim]  SANs: {cert_info['san_list']}[/dim]")
    
    return cert_info

def scan_single_port(target: str, port: int, timeout: int, ssl_config) -> Optional[Dict]:
    """Scan a single port for SSL/TLS with comprehensive security analysis."""
    try:
        # Test if port is open first
        with socket.create_connection((target, port), timeout=timeout) as test_sock:
            pass
    except (socket.timeout, socket.error):
        return None  # Port not open or unreachable

    try:
        context = ssl.create_default_context()
        context.check_hostname = False  # We might be scanning IPs
        context.verify_mode = ssl.CERT_NONE  # We're just gathering info
        
        with socket.create_connection((target, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=target) as ssock:
                # Extract SSL/TLS information
                ssl_version = ssock.version()
                cipher_suite = ssock.cipher()
                
                # Use comprehensive certificate extraction
                cert_info = extract_certificate_comprehensive(ssock, target)
                
                subject = cert_info['subject']
                issuer = cert_info['issuer']
                not_before = cert_info['not_before']
                not_after = cert_info['not_after']
                serial_number = cert_info['serial_number']
                signature_algorithm = cert_info['signature_algorithm']
                
                # Get certificate chain length safely
                chain_length = get_certificate_chain_length(ssock)
                
                # Extract certificate extensions
                cert_extensions = {
                    'san': cert_info['san_list'],
                    'key_usage': [],
                    'extended_key_usage': [],
                    'basic_constraints': {},
                    'crl_distribution_points': [],
                    'authority_info_access': []
                }
                
                # Perform security analysis
                cipher_security = analyze_cipher_security(cipher_suite, ssl_version)
                tls_security = analyze_tls_version_security(ssl_version or "Unknown")
                cert_validity = check_certificate_validity({
                    'notBefore': not_before,
                    'notAfter': not_after
                }, ssl_config)
                
                result = {
                    "target": target,
                    "port": port,
                    "ssl_version": ssl_version,
                    "cipher_suite": cipher_suite[0] if cipher_suite else "Unknown",
                    "cipher_strength": cipher_suite[2] if cipher_suite and len(cipher_suite) > 2 else "Unknown",
                    "subject": subject,
                    "issuer": issuer,
                    "valid_from": not_before,
                    "valid_until": not_after,
                    "cert_chain_length": chain_length,
                    "serial_number": cert_info.get("serial_number"),
                    "signature_algorithm": cert_info.get("signature_algorithm"),
                    "certificate_extensions": cert_extensions,
                    "cipher_security": cipher_security,
                    "tls_security": tls_security,
                    "certificate_validity": cert_validity,
                    "overall_security_score": (cipher_security.get("score", 100) + 
                                             tls_security.get("score", 100) + 
                                             (0 if cert_validity.get("warning_level") == "Critical" else 100)) // 3
                }
                
                return result

    except ssl.SSLError as e:
        console.print(f"[yellow]SSL Error on {target}:{port} - {e}[/yellow]")
        return None
    except Exception as e:
        console.print(f"[red]Error scanning {target}:{port} - {e}[/red]")
        return None

def scan(target: str, port: int = None, scan_additional_ports: bool = None):
    """
    Perform comprehensive SSL/TLS security scan.
    
    Args:
        target: Target host to scan
        port: Specific port to scan (uses config default if None)
        scan_additional_ports: Whether to scan additional ports from config
    """
    # Get configuration
    config = get_config()
    ssl_config = config.ssl_config
    
    # Validate target network
    if not config.validate_target_network(target):
        console.print(f"[red]Target {target} is not in allowed network ranges[/red]")
        return None
    
    console.print(f"[bold blue][SSL][/bold blue] Comprehensive SSL/TLS Security Analysis: {target}")
    
    # Determine ports to scan
    if port is not None:
        ports_to_scan = [port]
    else:
        ports_to_scan = [ssl_config.default_port]
        if scan_additional_ports or (scan_additional_ports is None):
            ports_to_scan.extend(ssl_config.additional_ports)
    
    console.print(f"[cyan]Scanning ports: {', '.join(map(str, ports_to_scan))}[/cyan]")
    console.print(f"[cyan]Timeout: {ssl_config.timeout}s[/cyan]")

    # Resolve host first
    try:
        socket.gethostbyname(target)
    except socket.gaierror:
        console.print(f"[red]Could not resolve {target}[/red]")
        return None

    # Scan all specified ports
    all_results = []
    primary_result = None
    
    for scan_port in ports_to_scan:
        console.print(f"[cyan]Analyzing SSL/TLS on port {scan_port}...[/cyan]")
        result = scan_single_port(target, scan_port, ssl_config.timeout, ssl_config)
        if result:
            all_results.append(result)
            if not primary_result:  # First successful result becomes primary
                primary_result = result

    if not all_results:
        console.print(f"[red]No SSL/TLS services found on {target}[/red]")
        return None

    # Print detailed results for each port
    for result in all_results:
        print_ssl_table(result, config)
        console.print()  # Add spacing between multiple results

    # Generate comprehensive security summary
    security_summary = generate_security_summary(all_results, ssl_config)
    
    # Prepare comprehensive data for reporting
    report_data = {
        "target": target,
        "scan_timestamp": datetime.utcnow().isoformat() + "Z",
        "ports_scanned": ports_to_scan,
        "ssl_results": all_results,
        "primary_result": primary_result,
        "security_summary": security_summary,
        "config_used": {
            "timeout": ssl_config.timeout,
            "default_port": ssl_config.default_port,
            "additional_ports": ssl_config.additional_ports,
            "expiry_thresholds": ssl_config.expiry_warning,
            "check_weak_ciphers": ssl_config.check_weak_ciphers,
            "weak_ciphers_checked": list(WEAK_CIPHERS.keys())
        }
    }

    # Save reports
    if primary_result:
        report.save_report(report_data, target, "ssl")
        report.save_report_html(report_data, target, "ssl")
        console.print("[green]SSL security analysis reports saved[/green]")

    # Display summary
    console.print(f"\n[bold]SSL/TLS Security Summary:[/bold]")
    console.print(f"[green]SSL/TLS services found: {len(all_results)}[/green]")
    
    if security_summary["critical_issues"]:
        console.print(f"[red bold]Critical security issues: {security_summary['critical_issues']}[/red bold]")
    
    if security_summary["expiring_certificates"]:
        console.print(f"[yellow]Expiring certificates: {len(security_summary['expiring_certificates'])}[/yellow]")
        for cert in security_summary["expiring_certificates"]:
            console.print(f"  • Port {cert['port']}: {cert['days_left']} days left")
    
    console.print(f"[cyan]Weak ciphers checked: {', '.join(WEAK_CIPHERS.keys())}[/cyan]")
    if security_summary["weak_ciphers_found"]:
        console.print(f"[red]Weak ciphers found: {', '.join(security_summary['weak_ciphers_found'])}[/red]")
    else:
        console.print("[green]No weak ciphers found[/green]")
    
    avg_score = security_summary["average_security_score"]
    if avg_score >= 80:
        score_color = "green"
    elif avg_score >= 60:
        score_color = "yellow"
    else:
        score_color = "red"
    
    console.print(f"[{score_color}]Overall security score: {avg_score}/100[/{score_color}]")

    return primary_result

def generate_security_summary(results: List[Dict], ssl_config) -> Dict:
    """Generate comprehensive security summary from SSL analysis results."""
    summary = {
        "total_ssl_ports": len(results),
        "ssl_versions_found": [],
        "weak_ciphers_found": [],
        "weak_ciphers_checked": list(WEAK_CIPHERS.keys()),
        "critical_issues": 0,
        "high_risk_issues": 0,
        "medium_risk_issues": 0,
        "expiring_certificates": [],
        "security_scores": [],
        "average_security_score": 0,
        "recommendations": []
    }
    
    for result in results:
        # Collect SSL versions
        if result.get("ssl_version"):
            summary["ssl_versions_found"].append(result["ssl_version"])
        
        # Analyze security issues
        cipher_security = result.get("cipher_security", {})
        tls_security = result.get("tls_security", {})
        cert_validity = result.get("certificate_validity", {})
        
        # Count security issues by severity
        for security_data in [cipher_security, tls_security]:
            security_level = security_data.get("security_level", "Good")
            if security_level == "Critical":
                summary["critical_issues"] += len(security_data.get("issues", []))
            elif security_level == "High Risk":
                summary["high_risk_issues"] += len(security_data.get("issues", []))
            elif security_level == "Medium Risk":
                summary["medium_risk_issues"] += len(security_data.get("issues", []))
        
        # Certificate validity issues
        if cert_validity.get("warning_level") == "Critical":
            summary["critical_issues"] += 1
        
        # Track expiring certificates
        if cert_validity.get("days_until_expiry") is not None:
            days_left = cert_validity["days_until_expiry"]
            if days_left <= ssl_config.expiry_warning["warning"]:
                summary["expiring_certificates"].append({
                    "port": result["port"],
                    "days_left": days_left,
                    "expires": result.get("valid_until")
                })
        
        # Collect weak ciphers
        if cipher_security.get("security_level") in ["Critical", "High Risk"]:
            cipher_name = result.get("cipher_suite", "Unknown")
            if cipher_name not in summary["weak_ciphers_found"]:
                summary["weak_ciphers_found"].append(cipher_name)
        
        # Security scores
        score = result.get("overall_security_score", 0)
        summary["security_scores"].append(score)
    
    # Calculate averages
    summary["ssl_versions_found"] = list(set(summary["ssl_versions_found"]))
    if summary["security_scores"]:
        summary["average_security_score"] = sum(summary["security_scores"]) // len(summary["security_scores"])
    
    # Generate recommendations
    if summary["critical_issues"] > 0:
        summary["recommendations"].append("Immediately address critical SSL/TLS security issues")
    
    if summary["weak_ciphers_found"]:
        summary["recommendations"].append("Disable weak cipher suites and upgrade to secure alternatives")
    
    if summary["expiring_certificates"]:
        summary["recommendations"].append("Renew expiring SSL certificates")
    
    if any("TLS" not in version for version in summary["ssl_versions_found"]):
        summary["recommendations"].append("Upgrade to TLS 1.2 or higher")
    
    if not summary["recommendations"]:
        summary["recommendations"].append("SSL/TLS configuration appears secure")
    
    return summary