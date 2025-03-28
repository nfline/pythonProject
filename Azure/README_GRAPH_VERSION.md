# Azure Network Traffic Analyzer (Resource Graph Version)

This advanced tool allows you to retrieve network traffic information from Azure Network Security Groups (NSGs) across multiple subscriptions and resource groups using Azure Resource Graph API. It exports the data to Excel format with comprehensive traffic details.

## Features

- Retrieve network traffic data via Azure NSG flow logs
- Filter traffic by IP address or subnet
- Work across multiple Azure subscriptions simultaneously
- Automatic cross-subscription resource discovery
- Parallel processing for improved performance
- Read device list from Excel file for batch processing
- Export results to organized Excel workbook with multiple sheets
- Automatic flow log enabling if not already enabled
- Configurable time range for data collection
- Detailed traffic information including source/destination addresses, ports, protocols, and traffic volume

## Prerequisites

- Python 3.6 or later
- Azure CLI installed and configured
- An active Azure subscription
- Appropriate permissions for Resource Graph API and NSG access
- User or service principal with Reader role (minimum) across target subscriptions

## Installation

1. Clone or download this repository
2. Install the required dependencies:

```
pip install -r requirements_graph.txt
```

Contents of requirements_graph.txt:
```
pandas
tqdm
openpyxl
ipaddress
azure-identity
azure-mgmt-resourcegraph
```

3. Make sure you have Azure CLI installed. If not, follow the [official installation guide](https://docs.microsoft.com/en-us/cli/azure/install-azure-cli).

4. Log in to your Azure account:

```
az login
```

## Usage

### Basic Usage

The Resource Graph version doesn't require a resource group to be specified - it can discover resources across all subscriptions you have access to.

#### Filtering by IP address:

```
python azure_traffic_analyzer_graph.py --ip 10.0.0.5 --output traffic_report.xlsx
```

#### Filtering by subnet:

```
python azure_traffic_analyzer_graph.py --subnet 10.0.0.0/24 --output traffic_report.xlsx
```

#### Limit to specific subscription:

```
python azure_traffic_analyzer_graph.py --subscription YOUR_SUBSCRIPTION_ID --ip 10.0.0.5 --output traffic_report.xlsx
```

#### Limit to specific resource group:

```
python azure_traffic_analyzer_graph.py --resource-group YOUR_RESOURCE_GROUP --ip 10.0.0.5 --output traffic_report.xlsx
```

#### Specify time range:

```
python azure_traffic_analyzer_graph.py --ip 10.0.0.5 --days 7 --hours 12 --output traffic_report.xlsx
```

#### Control parallel processing:

```
python azure_traffic_analyzer_graph.py --ip 10.0.0.5 --max-concurrent 5 --output traffic_report.xlsx
```

### Using Excel Device List

You can provide an Excel file with a list of devices to analyze traffic for multiple devices at once:

```
python azure_traffic_analyzer_graph.py --devices-file devices.xlsx --output traffic_report.xlsx
```

The Excel file should contain at least two columns:
- A column named "name" for device names
- A column named "ipaddr" for IP addresses

If your Excel uses different column names, you can specify them:

```
python azure_traffic_analyzer_graph.py --devices-file devices.xlsx --name-column "DeviceName" --ip-column "IPAddress" --output traffic_report.xlsx
```

### Command Line Options

| Option | Description |
|--------|-------------|
| `--ip` | IP address to filter results |
| `--subnet` | Subnet in CIDR notation (e.g., 10.0.0.0/24) |
| `--nsg` | Network Security Group name (optional) |
| `--subscription`, `-s` | Specific subscription ID (optional, omit to search all accessible subscriptions) |
| `--resource-group`, `-g` | Specific resource group (optional, omit to search all accessible resource groups) |
| `--days` | Number of days to look back (default: 1) |
| `--hours` | Number of hours to look back (default: 0) |
| `--output`, `-o` | Output Excel file path (default: azure_traffic_data.xlsx) |
| `--devices-file`, `-df` | Excel file containing device names and IP addresses |
| `--name-column` | Column name for device names in the Excel file (default: name) |
| `--ip-column` | Column name for IP addresses in the Excel file (default: ipaddr) |
| `--max-concurrent` | Maximum number of concurrent queries (default: 3) |
| `--verbose`, `-v` | Enable verbose output |

## Output Format

The tool exports the data to an Excel file with the following structure:

### When Using Device List Mode

1. **Device Summary** sheet:
   - Device Name
   - Total Traffic (bytes)
   - Connection Count

2. **Individual Device** sheets (one per device):
   - Full traffic details for each device

3. **All Traffic** sheet:
   - Combined traffic data from all devices

### When Using IP/Subnet Mode

1. **All Traffic** sheet:
   - timestamp: Time when the traffic occurred
   - source_ip: Source IP address
   - source_port: Source port
   - destination_ip: Destination IP address
   - destination_port: Destination port
   - protocol: Protocol (TCP/UDP)
   - direction: Traffic direction (Inbound/Outbound)
   - action: Allow/Deny action
   - traffic_bytes: Volume of traffic in bytes
   - rule: NSG rule that was applied

## Cross-Subscription Support

This version uses Azure Resource Graph API to search for resources across all subscriptions you have access to. Key benefits:

1. **Single-command cross-subscription search**: No need to run the tool multiple times for different subscriptions
2. **Efficient querying**: Resource Graph API is optimized for cross-subscription queries
3. **Parallel processing**: The tool performs multiple operations concurrently for better performance

## Required Permissions

To use this tool with Resource Graph API, your Azure account needs:

1. **Microsoft.ResourceGraph/resources/action** permission (included in the Reader role)
2. Appropriate permissions on NSGs and Network Watcher in each target subscription
3. Ability to create/manage storage accounts (if flow logs need to be enabled)

The easiest way to ensure proper permissions is to have at least Reader role on subscriptions and Contributor role on Network Watcher resource groups.

## Advanced Features

### Parallel Processing

The tool uses Python's concurrent.futures module to process multiple NSGs in parallel. You can control the degree of parallelism with the `--max-concurrent` parameter.

### Resource Discovery

The Resource Graph version uses advanced queries to find:
- Network interfaces with specific IP addresses
- Virtual machines within a specified subnet
- Network Security Groups across subscriptions

## Troubleshooting

### Resource Graph API Errors

If you encounter errors with Resource Graph API:

1. Verify your account has the necessary permissions (Reader role or equivalent)
2. Check that the Azure libraries are installed correctly
3. Try running with the `--verbose` flag for more detailed output

### No Data in Output

If you're not seeing any data in the output Excel file:

1. Verify the flow logs are enabled for your NSGs
2. Check that the IP address or subnet exists in your Azure environment
3. Try extending the time range (--days parameter)
4. Ensure your Azure account has appropriate permissions

### Authentication Issues

The tool uses DefaultAzureCredential which attempts several authentication methods:

1. Environment variables
2. Managed identity
3. Visual Studio Code credentials
4. Azure CLI credentials
5. Interactive browser authentication

If authentication fails, try explicitly logging in with `az login` before running the tool.

## FAQ

### Q: How does this version differ from the standard CLI version?
A: This version uses Azure Resource Graph API to query across multiple subscriptions simultaneously, and processes NSGs in parallel for better performance.

### Q: Does this require additional permissions compared to the CLI version?
A: Yes, it requires the Microsoft.ResourceGraph/resources/action permission, which is included in the Reader role.

### Q: Will this tool work in Azure government clouds?
A: Yes, but you may need to specify the cloud environment through Azure CLI login before running the tool.

### Q: Is this tool suitable for very large Azure environments?
A: Yes, the Resource Graph version is specifically designed for large environments with multiple subscriptions and many NSGs.

## License

This project is licensed under the MIT License - see the LICENSE file for details. 