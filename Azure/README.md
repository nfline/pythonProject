# Azure Network Traffic Analyzer

This tool allows you to retrieve network traffic information from Azure Network Security Groups (NSGs) and export it to Excel format. It uses Azure CLI to collect flow log data for specific IP addresses or subnets.

## Features

- Retrieve network traffic data via Azure NSG flow logs
- Filter traffic by IP address or subnet
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

3. Make sure you have Azure CLI installed. If not, follow the [official installation guide](https://docs.microsoft.com/en-us/cli/azure/install-azure-cli).

4. Log in to your Azure account:

```
az login
```

## Usage

### Basic Usage

To analyze traffic for a specific IP address:

```
python azure_traffic_analyzer.py --resource-group YOUR_RESOURCE_GROUP --ip 10.0.0.5 --output traffic_report.xlsx
```

To analyze traffic for a subnet:

```
python azure_traffic_analyzer.py --resource-group YOUR_RESOURCE_GROUP --subnet 10.0.0.0/24 --output traffic_report.xlsx
```

To analyze traffic for a specific time range:

```
python azure_traffic_analyzer.py --resource-group YOUR_RESOURCE_GROUP --ip 10.0.0.5 --days 7 --hours 12 --output traffic_report.xlsx
```

### Using Excel Device List

You can provide an Excel file with a list of devices to analyze traffic for multiple devices at once:

```
python azure_traffic_analyzer.py --resource-group YOUR_RESOURCE_GROUP --devices-file devices.xlsx --output traffic_report.xlsx
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
| `--resource-group`, `-g` | Azure Resource Group (required) |
| `--ip` | IP address to filter results |
| `--subnet` | Subnet in CIDR notation (e.g., 10.0.0.0/24) |
| `--nsg` | Network Security Group name |
| `--days` | Number of days to look back (default: 1) |
| `--hours` | Number of hours to look back (default: 0) |
| `--output`, `-o` | Output Excel file path (default: azure_traffic_data.xlsx) |
| `--devices-file`, `-d` | Excel file containing device names and IP addresses |
| `--name-column` | Column name for device names in the Excel file (default: name) |
| `--ip-column` | Column name for IP addresses in the Excel file (default: ipaddr) |

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

## Notes

- The tool automatically enables flow logs if they are not already enabled
- Flow logs may take some time to generate in Azure, so recent traffic might not appear immediately
- For best results, enable flow logs some time before running this tool
- Large time ranges may result in large datasets and longer processing times

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

## License

This project is licensed under the MIT License - see the LICENSE file for details.
