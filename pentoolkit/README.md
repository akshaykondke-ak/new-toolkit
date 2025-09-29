Complete Working Command List
Based on your current implementation, here are ALL available commands:

🎯 Scan Commands

bashpentoolkit scan run <target>                    # Run comprehensive scans
pentoolkit scan run <target> -m nmap,ssl        # Run specific modules  
pentoolkit scan run <target> --scan-type syn    # Use specific nmap scan type
pentoolkit scan run <target> -p 80,443,8080     # Scan specific ports
pentoolkit scan run <target> --scripts vuln     # Run NSE scripts
pentoolkit scan run <target> -T4                # Set timing template
pentoolkit scan interactive                     # Interactive scan builder


📊 Results Commands

bashpentoolkit results list                        # List recent scans
pentoolkit results list --target example.com   # Filter by target
pentoolkit results list --days 7              # Show last 7 days
pentoolkit results show <scan_id>             # Show detailed scan results
pentoolkit results search <query>             # Search scan history
pentoolkit results dashboard                  # Launch web dashboard


⚙️ Config Commands

bashpentoolkit config show                        # Show current config
pentoolkit config show --section nmap         # Show specific section
pentoolkit config show --locations           # Show search paths
pentoolkit config create                      # Create default config
pentoolkit config create --force             # Overwrite existing
pentoolkit config create --global            # Create in home directory
pentoolkit config path                       # Show config file paths
pentoolkit config migrate                    # Migrate old configs
pentoolkit config validate                   # Validate configuration
pentoolkit config edit                       # Open config in editor
pentoolkit config reset                      # Reset to defaults
pentoolkit config test-wordlist              # Test wordlist access
pentoolkit config backup                     # Backup current config


🔧 Admin Commands

bashpentoolkit admin cleanup                      # Clean old reports/data
pentoolkit admin cleanup --days 15           # Clean data older than 15 days
pentoolkit admin cleanup --dry-run           # Show what would be deleted
pentoolkit admin stats                       # Show system statistics