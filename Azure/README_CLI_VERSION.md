# Azure Network Traffic Analyzer (CLI Version)

This tool allows you to retrieve network traffic information from Azure Network Security Groups (NSGs) and export it to Excel format. It uses Azure CLI to collect flow log data for specific IP addresses or subnets across resource groups.

## Features

- Retrieve network traffic data via Azure NSG flow logs
- Filter traffic by IP address or subnet
- Automatic resource group discovery for IP addresses
- Scan across multiple resource groups with a single command
- Read device list from Excel file for batch processing
- Export results to organized Excel workbook with multiple sheets
- Automatic flow log enabling if not already enabled
- Configurable time range for data collection
- Detailed traffic information including source/destination addresses, ports, protocols, and traffic volume

## Prerequisites

- Python 3.6 or later
- Azure CLI installed and configured
- An active Azure subscription
- Appropriate permissions to access Network Security Groups and enable flow logs

## Installation

1. Clone or download this repository
2. Install the required dependencies:

```
pip install -r requirements.txt
```

Contents of requirements.txt:
```
pandas
tqdm
openpyxl
ipaddress
```

3. Make sure you have Azure CLI installed. If not, follow the [official installation guide](https://docs.microsoft.com/en-us/cli/azure/install-azure-cli).

4. Log in to your Azure account:

```
az login
```

## Usage

### Basic Usage

You must specify at least one of the following options:
- A specific resource group with `--resource-group`
- Scan all resource groups with `--all-resource-groups`
- Auto-discover resource groups based on IP with `--discover-resource-group`

#### Filtering by IP address:

```
python azure_traffic_analyzer.py --resource-group YOUR_RESOURCE_GROUP --ip 10.0.0.5 --output traffic_report.xlsx
```

#### Filtering by subnet:

```
python azure_traffic_analyzer.py --resource-group YOUR_RESOURCE_GROUP --subnet 10.0.0.0/24 --output traffic_report.xlsx
```

#### Auto-discovering resource group for a specific IP:

```
python azure_traffic_analyzer.py --discover-resource-group --ip 10.0.0.5 --output traffic_report.xlsx
```

#### Scanning all accessible resource groups:

```
python azure_traffic_analyzer.py --all-resource-groups --ip 10.0.0.5 --output traffic_report.xlsx
```

#### Specify time range:

```
python azure_traffic_analyzer.py --resource-group YOUR_RESOURCE_GROUP --ip 10.0.0.5 --days 7 --hours 12 --output traffic_report.xlsx
```

### Using Excel Device List

You can provide an Excel file with a list of devices to analyze traffic for multiple devices at once:

```
python azure_traffic_analyzer.py --discover-resource-group --devices-file devices.xlsx --output traffic_report.xlsx
```

The Excel file should contain at least two columns:
- A column named "name" for device names
- A column named "ipaddr" for IP addresses

If your Excel uses different column names, you can specify them:

```
python azure_traffic_analyzer.py --resource-group YOUR_RESOURCE_GROUP --devices-file devices.xlsx --name-column "DeviceName" --ip-column "IPAddress" --output traffic_report.xlsx
```

### Command Line Options

| Option | Description |
|--------|-------------|
| `--resource-group`, `-g` | Azure Resource Group |
| `--all-resource-groups`, `-a` | Scan all accessible resource groups |
| `--discover-resource-group`, `-d` | Automatically discover resource group for the given IP or devices |
| `--ip` | IP address to filter results |
| `--subnet` | Subnet in CIDR notation (e.g., 10.0.0.0/24) |
| `--nsg` | Network Security Group name |
| `--days` | Number of days to look back (default: 1) |
| `--hours` | Number of hours to look back (default: 0) |
| `--output`, `-o` | Output Excel file path (default: azure_traffic_data.xlsx) |
| `--devices-file`, `-df` | Excel file containing device names and IP addresses |
| `--name-column` | Column name for device names in the Excel file (default: name) |
| `--ip-column` | Column name for IP addresses in the Excel file (default: ipaddr) |
| `--max-resource-groups` | Maximum number of resource groups to scan when auto-discovering (default: 5) |

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

## Cross-Resource Group Support

This tool provides several ways to work with multiple resource groups:

1. **Auto-discover resource groups**: The tool will automatically find the resource group(s) that contain the specified IP address.
2. **Scan all resource groups**: The tool will scan all resource groups that your Azure account has access to.
3. **Specify a single resource group**: If you know exactly which resource group to use.

For large environments, auto-discovery is recommended when you know the IP but not the resource group.

## Notes

- The tool automatically enables flow logs if they are not already enabled
- Flow logs may take some time to generate in Azure, so recent traffic might not appear immediately
- For best results, enable flow logs some time before running this tool
- Large time ranges may result in large datasets and longer processing times
- The auto-discovery feature uses Azure CLI to search for network interfaces with the specified IP address

## Troubleshooting

### No Data in Output

If you're not seeing any data in the output Excel file:

1. Verify the flow logs are enabled for your NSGs
2. Check that the IP address or subnet exists in your Azure environment
3. Try extending the time range (--days parameter)
4. Ensure your Azure account has appropriate permissions

### Azure CLI Errors

If you encounter Azure CLI errors:

1. Make sure you're logged in (`az login`)
2. Check that you have the correct permissions for the resource group
3. Update Azure CLI to the latest version
4. Verify the resource group name is correct

### Resource Group Discovery Issues

If automatic resource group discovery isn't working:

1. Verify that your account has permissions to list network interfaces across subscriptions
2. Try using the `--all-resource-groups` flag instead
3. Check that the IP address is correctly specified and exists in your Azure environment

## FAQ

### Q: How many resource groups will be scanned by default?
A: When using auto-discovery, the tool limits scanning to 5 resource groups by default to avoid excessive processing. You can change this with the `--max-resource-groups` parameter.

### Q: Will this tool work for resources across multiple subscriptions?
A: No, this version only works within the subscription you're currently logged into with Azure CLI. For cross-subscription support, use the Resource Graph version.

### Q: Does this tool require any special permissions?
A: Yes, your Azure account needs permissions to:
   - List resource groups
   - View network interfaces
   - Read and configure NSG flow logs
   - Create storage accounts (if flow logs aren't already enabled)

## License

This project is licensed under the MIT License - see the LICENSE file for details. 