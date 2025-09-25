# pentoolkit/utils/config.py
import os
import yaml
from pathlib import Path
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field

# Determine the project root directory
PROJECT_ROOT = Path(__file__).parent.parent.parent.parent
DEFAULT_CONFIG_PATH = PROJECT_ROOT / "config.yaml"

# Environment variable substitution
def _substitute_env_vars(value: Any) -> Any:
    """Recursively substitute environment variables in config values."""
    if isinstance(value, str):
        # Handle ${VAR} and ${VAR:-default} syntax
        import re
        def replace_env(match):
            var_expr = match.group(1)
            if ":-" in var_expr:
                var_name, default_value = var_expr.split(":-", 1)
                return os.getenv(var_name, default_value)
            else:
                return os.getenv(var_expr, "")
        
        return re.sub(r'\$\{([^}]+)\}', replace_env, value)
    elif isinstance(value, dict):
        return {k: _substitute_env_vars(v) for k, v in value.items()}
    elif isinstance(value, list):
        return [_substitute_env_vars(item) for item in value]
    else:
        return value


@dataclass
class GlobalConfig:
    """Global configuration settings."""
    default_timeout: int = 30
    default_threads: int = 40
    output: Dict[str, Any] = field(default_factory=lambda: {
        "colored_output": True,
        "log_level": "INFO",
        "save_raw_output": True,
        "report_formats": "both"
    })


@dataclass 
class NmapConfig:
    """Nmap scanner configuration."""
    default_args: str = "-sV"
    scan_types: Dict[str, str] = field(default_factory=lambda: {
        "default": "-sV",
        "syn": "-sS -sV", 
        "udp": "-sU -sV --top-ports 1000",
        "aggressive": "-A -sV -O",
        "stealth": "-sS -sV -f -T2",
        "discovery": "-sn"
    })
    timeout: int = 300
    host_timeout: int = 30
    skip_ping: bool = False
    default_nse_scripts: str = ""
    nse_script_dir: str = ""


@dataclass
class SslConfig:
    """SSL scanner configuration."""
    default_port: int = 443
    additional_ports: List[int] = field(default_factory=lambda: [8443, 8080, 9443])
    timeout: int = 15
    expiry_warning: Dict[str, int] = field(default_factory=lambda: {
        "critical": 7,
        "warning": 30
    })
    test_versions: List[str] = field(default_factory=lambda: ["TLSv1.2", "TLSv1.3"])
    check_weak_ciphers: bool = True


@dataclass
class WhoisConfig:
    """WHOIS lookup configuration."""
    timeout: int = 20
    use_system_fallback: bool = True
    custom_servers: Dict[str, str] = field(default_factory=dict)
    deep_lookup: bool = False


@dataclass
class WafConfig:
    """WAF detection configuration."""
    timeout: int = 15
    use_wafw00f: bool = True
    wafw00f_timeout: int = 60
    http: Dict[str, Any] = field(default_factory=lambda: {
        "user_agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
        "follow_redirects": True,
        "max_redirects": 5,
        "verify_ssl": False
    })
    test_payloads: List[str] = field(default_factory=lambda: [
        "' OR '1'='1",
        "<script>alert(1)</script>", 
        "../../etc/passwd",
        "UNION SELECT"
    ])
    custom_signatures: Dict[str, Any] = field(default_factory=dict)


@dataclass
class WebReconConfig:
    """Web reconnaissance configuration."""
    wordlists: List[str] = field(default_factory=lambda: [
        "/usr/share/wordlists/dirb/common.txt",
        "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt",
        "/home/admin-1/Desktop/common.txt",
        "./wordlists/common.txt"
    ])
    default_extensions: str = "php,html,htm,asp,aspx,jsp,js,txt,xml,json,bak,old,zip,tar.gz"
    ffuf: Dict[str, Any] = field(default_factory=lambda: {
        "threads": 40,
        "timeout": 10,
        "rate_limit": 0,
        "follow_redirects": False,
        "match_codes": "200,204,301,302,307,401,403,405,500",
        "filter_size": "",
        "filter_words": "",
        "headers": {}
    })
    recursive_scan: bool = False
    recursive_depth: int = 2


@dataclass
class ReportingConfig:
    """Reporting configuration."""
    output_dir: str = "./reports"
    naming_convention: str = "both"
    auto_open_reports: bool = False
    include_screenshots: bool = False
    template_dir: str = "./templates"
    custom_css: str = ""
    retention_days: int = 90


@dataclass
class NetworkConfig:
    """Network configuration."""
    proxy: Dict[str, Any] = field(default_factory=lambda: {
        "enabled": False,
        "http_proxy": "",
        "https_proxy": "",
        "no_proxy": "localhost,127.0.0.1"
    })
    dns_servers: List[str] = field(default_factory=list)
    source_ip: str = ""
    rate_limit: Dict[str, Any] = field(default_factory=lambda: {
        "enabled": False,
        "requests_per_second": 10
    })


@dataclass
class SecurityConfig:
    """Security configuration."""
    safe_mode: bool = False
    allowed_networks: List[str] = field(default_factory=lambda: [
        "10.0.0.0/8",
        "172.16.0.0/12", 
        "192.168.0.0/16",
        "127.0.0.0/8"
    ])
    blocked_networks: List[str] = field(default_factory=list)
    confirm_external_scans: bool = True


class ConfigManager:
    """Manages configuration loading and access."""
    
    def __init__(self, config_path: Optional[Path] = None):
        self.config_path = config_path or DEFAULT_CONFIG_PATH
        self._config_data: Dict[str, Any] = {}
        self.load_config()
    
    def load_config(self) -> None:
        """Load configuration from YAML file."""
        if not self.config_path.exists():
            print(f"[!] Config file not found at {self.config_path}, using defaults")
            self._config_data = {}
            return
        
        try:
            with open(self.config_path, 'r') as f:
                raw_config = yaml.safe_load(f) or {}
                # Substitute environment variables
                self._config_data = _substitute_env_vars(raw_config)
            print(f"[+] Loaded configuration from {self.config_path}")
        except Exception as e:
            print(f"[!] Error loading config file {self.config_path}: {e}")
            print("[!] Using default configuration")
            self._config_data = {}
    
    def get_section(self, section: str, default: Dict = None) -> Dict[str, Any]:
        """Get a configuration section."""
        return self._config_data.get(section, default or {})
    
    def get_value(self, section: str, key: str, default: Any = None) -> Any:
        """Get a specific configuration value."""
        section_data = self.get_section(section)
        return section_data.get(key, default)
    
    @property
    def global_config(self) -> GlobalConfig:
        """Get global configuration."""
        data = self.get_section("global")
        return GlobalConfig(
            default_timeout=data.get("default_timeout", 30),
            default_threads=data.get("default_threads", 40),
            output=data.get("output", {
                "colored_output": True,
                "log_level": "INFO", 
                "save_raw_output": True,
                "report_formats": "both"
            })
        )
    
    @property
    def nmap_config(self) -> NmapConfig:
        """Get Nmap configuration."""
        data = self.get_section("nmap")
        config = NmapConfig()
        if data:
            config.default_args = data.get("default_args", config.default_args)
            config.scan_types.update(data.get("scan_types", {}))
            config.timeout = data.get("timeout", config.timeout)
            config.host_timeout = data.get("host_timeout", config.host_timeout)
            config.skip_ping = data.get("skip_ping", config.skip_ping)
            config.default_nse_scripts = data.get("default_nse_scripts", config.default_nse_scripts)
            config.nse_script_dir = data.get("nse_script_dir", config.nse_script_dir)
        return config
    
    @property
    def ssl_config(self) -> SslConfig:
        """Get SSL configuration."""
        data = self.get_section("ssl")
        config = SslConfig()
        if data:
            config.default_port = data.get("default_port", config.default_port)
            config.additional_ports = data.get("additional_ports", config.additional_ports)
            config.timeout = data.get("timeout", config.timeout)
            config.expiry_warning.update(data.get("expiry_warning", {}))
            config.test_versions = data.get("test_versions", config.test_versions)
            config.check_weak_ciphers = data.get("check_weak_ciphers", config.check_weak_ciphers)
        return config
    
    @property
    def whois_config(self) -> WhoisConfig:
        """Get WHOIS configuration."""
        data = self.get_section("whois")
        config = WhoisConfig()
        if data:
            config.timeout = data.get("timeout", config.timeout)
            config.use_system_fallback = data.get("use_system_fallback", config.use_system_fallback)
            config.custom_servers.update(data.get("custom_servers", {}))
            config.deep_lookup = data.get("deep_lookup", config.deep_lookup)
        return config
    
    @property
    def waf_config(self) -> WafConfig:
        """Get WAF detection configuration."""
        data = self.get_section("waf")
        config = WafConfig()
        if data:
            config.timeout = data.get("timeout", config.timeout)
            config.use_wafw00f = data.get("use_wafw00f", config.use_wafw00f)
            config.wafw00f_timeout = data.get("wafw00f_timeout", config.wafw00f_timeout)
            config.http.update(data.get("http", {}))
            config.test_payloads = data.get("test_payloads", config.test_payloads)
            config.custom_signatures.update(data.get("custom_signatures", {}))
        return config
    
    @property
    def web_recon_config(self) -> WebReconConfig:
        """Get web reconnaissance configuration."""
        data = self.get_section("web_recon")
        config = WebReconConfig()
        if data:
            config.wordlists = data.get("wordlists", config.wordlists)
            config.default_extensions = data.get("default_extensions", config.default_extensions)
            config.ffuf.update(data.get("ffuf", {}))
            config.recursive_scan = data.get("recursive_scan", config.recursive_scan)
            config.recursive_depth = data.get("recursive_depth", config.recursive_depth)
        return config
    
    @property
    def reporting_config(self) -> ReportingConfig:
        """Get reporting configuration."""
        data = self.get_section("reporting")
        config = ReportingConfig()
        if data:
            config.output_dir = data.get("output_dir", config.output_dir)
            config.naming_convention = data.get("naming_convention", config.naming_convention)
            config.auto_open_reports = data.get("auto_open_reports", config.auto_open_reports)
            config.include_screenshots = data.get("include_screenshots", config.include_screenshots)
            config.template_dir = data.get("template_dir", config.template_dir)
            config.custom_css = data.get("custom_css", config.custom_css)
            config.retention_days = data.get("retention_days", config.retention_days)
        return config
    
    @property
    def network_config(self) -> NetworkConfig:
        """Get network configuration."""
        data = self.get_section("network")
        config = NetworkConfig()
        if data:
            config.proxy.update(data.get("proxy", {}))
            config.dns_servers = data.get("dns_servers", config.dns_servers)
            config.source_ip = data.get("source_ip", config.source_ip)
            config.rate_limit.update(data.get("rate_limit", {}))
        return config
    
    @property  
    def security_config(self) -> SecurityConfig:
        """Get security configuration."""
        data = self.get_section("security")
        config = SecurityConfig()
        if data:
            config.safe_mode = data.get("safe_mode", config.safe_mode)
            config.allowed_networks = data.get("allowed_networks", config.allowed_networks)
            config.blocked_networks = data.get("blocked_networks", config.blocked_networks)
            config.confirm_external_scans = data.get("confirm_external_scans", config.confirm_external_scans)
        return config
    
    def find_wordlist(self, wordlist_paths: List[str]) -> Optional[str]:
        """Find the first existing wordlist from a list of paths."""
        for path in wordlist_paths:
            expanded_path = os.path.expanduser(path)
            if os.path.exists(expanded_path):
                return expanded_path
        return None
    
    def validate_target_network(self, target: str) -> bool:
        """Validate if target is allowed based on security configuration."""
        import ipaddress
        import socket
        
        security = self.security_config
        return True
        
        # Skip validation in safe mode
        if security.safe_mode:
            return True
        
        try:
            # Try to resolve hostname to IP if needed
            try:
                ip = ipaddress.ip_address(target)
            except ValueError:
                # It's a hostname, resolve it
                ip = ipaddress.ip_address(socket.gethostbyname(target))
            
            # Check blocked networks first
            for blocked_net in security.blocked_networks:
                if ip in ipaddress.ip_network(blocked_net, strict=False):
                    return False
            
            # Check allowed networks
            if security.allowed_networks:
                for allowed_net in security.allowed_networks:
                    if ip in ipaddress.ip_network(allowed_net, strict=False):
                        return True
                return False  # Not in any allowed network
            
            return True  # No restrictions
            
        except Exception:
            # If we can't determine the IP, allow it (user responsibility)
            return True


# Global config manager instance
config_manager = ConfigManager()

# Convenience functions for easy access
def get_config() -> ConfigManager:
    """Get the global configuration manager."""
    return config_manager

def reload_config() -> None:
    """Reload configuration from file."""
    global config_manager
    config_manager.load_config()

def get_wordlist_path(wordlist_paths: List[str]) -> str:
    """Get the first existing wordlist path or return the first one as default."""
    found = config_manager.find_wordlist(wordlist_paths)
    if found:
        return found
    return wordlist_paths[0] if wordlist_paths else "/usr/share/wordlists/dirb/common.txt"