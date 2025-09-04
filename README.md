# Server Uptime Monitor

PowerShell script for automated collection of server uptime and availability statistics across the Active Directory domain. The tool queries all servers in the specified OU, checks their status, and calculates precise uptime using multiple fallback methods.

## Key Features

- **Multi-method uptime detection**: Uses WMI, CIM, Registry, and systeminfo as fallback methods
- **Active Directory integration**: Automatically discovers all servers from specified OU
- **Comprehensive reporting**: Generates detailed CSV reports with timestamps and status information
- **Visual progress tracking**: Real-time progress bar and color-coded status output

## Usage

Simply run the script to generate an uptime report. The tool will:
1. Discover all enabled servers in the "OU=Servers,DC=domain,DC=com" OU
2. Test connectivity to each server
3. Calculate uptime using the most reliable available method
4. Generate a timestamped CSV report in `C:\Logs\Uptime\`

No parameters required for basic operation. Customize `$OutputDirectory` and `$SearchBase` in the script for different environments.