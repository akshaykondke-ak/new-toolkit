# Install in development mode
pip install -e ./pentoolkit

# Basic usage
pentoolkit config create
pentoolkit scan run target.com --modules nmap,ssl,web_recon
pentoolkit report summary target.com
pentoolkit report serve

# View current nmap config
pentoolkit config nmap show

# Change default scan type
pentoolkit config nmap set-scan-type aggressive

# Add custom nmap arguments
pentoolkit scan run target.com --nmap-args "-sC -O -A"

# List available scan types
pentoolkit config nmap list-scan-types

# Current (awkward):
pentoolkit scan run target.com --nmap-args "-sS -O -A"

# Better approach:
pentoolkit scan run target.com --scan-type aggressive
pentoolkit scan run target.com --ports 1-1000 --scripts vuln,auth
pentoolkit scan run target.com --custom-nmap "-sS -O --script-timeout 30s"