# Azure Network Traffic Analyzer (Resource Graph Version)

This tool analyzes Azure Network Traffic by querying flow logs across multiple subscriptions and resource groups. It uses Azure Resource Graph API for efficient discovery of resources and Azure CLI for retrieving flow log data.

## Important Note: Read-Only Mode

This script operates in **read-only mode by default**. It will:
- **NOT** create any storage accounts
- **NOT** enable Network Watcher
- **NOT** configure flow logs
- **ONLY** read from NSGs that already have flow logs enabled

This ensures the script is safe to run in production environments and won't modify your Azure configuration.

## Features

- Search for traffic by IP address or subnet
- Support for multiple subscriptions and resource groups
- Export results to Excel with formatted worksheets
- Process devices in bulk from an Excel input file
- Parallel processing for improved performance
- Built-in diagnostic tools for troubleshooting
- Production-safe read-only operation

## Prerequisites

- Python 3.6 or later
- Azure CLI installed and configured
- Azure subscription with appropriate permissions
- Network Watcher and flow logs **must be pre-configured** on NSGs you want to analyze

## Installation

1. Clone or download this repository
2. Install dependencies:

```bash
pip install -r requirements_graph.txt
```

3. Ensure Azure CLI is installed:
   - Windows: https://docs.microsoft.com/en-us/cli/azure/install-azure-cli-windows
   - macOS: https://docs.microsoft.com/en-us/cli/azure/install-azure-cli-macos
   - Linux: https://docs.microsoft.com/en-us/cli/azure/install-azure-cli-linux

4. Log in to Azure:

```bash
az login
```

## Usage

### Basic Usage

Search for traffic related to a specific IP address:

```bash
python azure_traffic_analyzer_graph.py --ip 10.0.0.50 --output traffic_report.xlsx
```

Search for traffic in a subnet:

```bash
python azure_traffic_analyzer_graph.py --subnet 10.0.0.0/24 --output subnet_traffic.xlsx
```

### Advanced Options

Filter by specific Network Security Group:

```bash
python azure_traffic_analyzer_graph.py --ip 10.0.0.50 --nsg my-nsg --output traffic_report.xlsx
```

Limit search to specific subscription:

```bash
python azure_traffic_analyzer_graph.py --ip 10.0.0.50 --subscription "00000000-0000-0000-0000-000000000000" --output traffic_report.xlsx
```

Limit search to specific resource group:

```bash
python azure_traffic_analyzer_graph.py --ip 10.0.0.50 --resource-group "my-resource-group" --output traffic_report.xlsx
```

Adjust time range (default is 1 day):

```bash
python azure_traffic_analyzer_graph.py --ip 10.0.0.50 --days 7 --output traffic_report.xlsx
```

Process multiple devices from Excel file:

```bash
python azure_traffic_analyzer_graph.py --devices-file devices.xlsx --output traffic_report.xlsx
```

Run diagnostic tests to troubleshoot Azure CLI issues:

```bash
python azure_traffic_analyzer_graph.py --diagnose
```

### Preparing Your Azure Environment

Since this script operates in read-only mode, you need to ensure that:

1. Network Watcher is enabled in your regions
2. Flow logs are enabled on the NSGs you want to analyze
3. A storage account is configured for these flow logs

You can configure these through the Azure Portal or Azure CLI before running this script.

### Full Command Reference

```
usage: azure_traffic_analyzer_graph.py [-h] [--ip IP] [--subnet SUBNET] [--nsg NSG]
                                      [--subscription SUBSCRIPTION] [--resource-group RESOURCE_GROUP]
                                      [--days DAYS] [--hours HOURS] [--output OUTPUT]
                                      [--devices-file DEVICES_FILE] [--name-column NAME_COLUMN]
                                      [--ip-column IP_COLUMN] [--max-concurrent MAX_CONCURRENT]
                                      [--verbose] [--diagnose] [--read-only]

Analyze Azure Network Traffic using Resource Graph API and export to Excel

optional arguments:
  -h, --help            show this help message and exit
  --ip IP               IP address to filter results
  --subnet SUBNET       Subnet in CIDR notation (e.g., 10.0.0.0/24) to filter results
  --nsg NSG             Network Security Group name (optional)
  --subscription SUBSCRIPTION, -s SUBSCRIPTION
                        Specific subscription ID (optional, omit to search all accessible subscriptions)
  --resource-group RESOURCE_GROUP, -g RESOURCE_GROUP
                        Specific resource group (optional, omit to search all accessible resource groups)
  --days DAYS           Number of days to look back (default: 1)
  --hours HOURS         Number of hours to look back (default: 0)
  --output OUTPUT, -o OUTPUT
                        Output Excel file path
  --devices-file DEVICES_FILE, -df DEVICES_FILE
                        Excel file containing device names and IP addresses
  --name-column NAME_COLUMN
                        Column name for device names in the Excel file (default: name)
  --ip-column IP_COLUMN
                        Column name for IP addresses in the Excel file (default: ipaddr)
  --max-concurrent MAX_CONCURRENT
                        Maximum number of concurrent queries (default: 3)
  --verbose, -v         Enable verbose output
  --diagnose            Run diagnostic tests and exit
  --read-only           Run in read-only mode, do not modify any Azure configurations (default: True)
```

## Troubleshooting

### Azure CLI Not Found

If you see an error about Azure CLI not being found, ensure that:

1. Azure CLI is installed correctly
2. The installation directory is in your system PATH
3. Try running the script with the `--diagnose` flag to find more details:

```bash
python azure_traffic_analyzer_graph.py --diagnose
```

### Subprocess Execution Issues on Windows

On Windows systems, you might encounter issues with subprocess command execution. Try:

1. Running PowerShell or Command Prompt as Administrator
2. Ensuring Azure CLI commands work directly from your command line
3. Using the `--diagnose` flag for detailed debugging information

### No Subscriptions Found

If the script cannot find subscriptions:

1. Confirm you are logged in with `az login`
2. Verify you have access to subscriptions in Azure Portal
3. Try running `az account list` directly in your terminal
4. Check if your Azure account requires multi-factor authentication
5. Use the `--diagnose` flag to run diagnostic tests

### Flow Logs Not Available

If flow logs aren't available:

1. Ensure Network Watcher is enabled in your region
2. Wait a few minutes as flow logs may take time to activate
3. Verify you have permissions to view/enable flow logs
4. Check if NSG resource has been created recently (flow logs need time to populate)

## Excel File Format for Device Input

When using the `--devices-file` option, the Excel file should contain at least two columns:

- A column for device names (default column name: `name`)
- A column for IP addresses (default column name: `ipaddr`)

Example format:

| name        | ipaddr       |
|-------------|--------------|
| webserver01 | 10.0.0.50    |
| dbserver01  | 10.0.0.51    |
| appserver01 | 10.0.1.100   |

You can customize the column names using the `--name-column` and `--ip-column` parameters.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the LICENSE file for details. 