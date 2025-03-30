# Azure Network Traffic Analyzer

This tool allows you to retrieve network traffic information from Azure Network Security Groups (NSGs) and export it to Excel format. It is available in two versions, each with different capabilities and requirements.

## Version Comparison

| Feature | CLI Version | Resource Graph Version |
|---------|-------------|------------------------|
| **File name** | `azure_traffic_analyzer.py` | `azure_traffic_analyzer_graph.py` |
| **README** | [CLI Version README](README_CLI_VERSION.md) | [Graph Version README](README_GRAPH_VERSION.md) |
| **Multi-resource group** | ✅ (within one subscription) | ✅ |
| **Multi-subscription** | ❌ | ✅ |
| **Auto-discovery** | ✅ (within current subscription) | ✅ (across all subscriptions) |
| **Parallel processing** | ❌ | ✅ |
| **Additional permissions** | Standard Azure CLI | Resource Graph API permissions |
| **Additional dependencies** | None | Azure SDK libraries |

## Choose the Right Version

### Use the CLI Version if:
- You work within a single subscription
- You prefer minimal dependencies
- You have standard Azure CLI permissions
- You need to specify resource groups explicitly

```
python azure_traffic_analyzer.py --resource-group YOUR_RESOURCE_GROUP --subnet 10.0.0.0/24 --output traffic_report.xlsx
```

### Use the Resource Graph Version if:
- You need to work across multiple subscriptions
- You want faster processing via parallelization
- You have appropriate Resource Graph API permissions
- You want automatic cross-subscription resource discovery

```
python azure_traffic_analyzer_graph.py --subnet 10.0.0.0/24 --output traffic_report.xlsx
```

## Common Features in Both Versions

Both versions support:
- Filtering by IP address or subnet
- Reading device lists from Excel files
- Configurable time ranges
- Detailed traffic analysis
- Automatic flow log enabling
- Comprehensive Excel reports with multiple sheets

## Prerequisites

- Python 3.6 or later
- Azure CLI installed and configured
- An active Azure subscription
- Appropriate permissions for NSG access

## Quick Install

### CLI Version:
```
pip install pandas tqdm openpyxl ipaddress
```

### Resource Graph Version:
```
pip install pandas tqdm openpyxl ipaddress azure-identity azure-mgmt-resourcegraph
```

## Detailed Documentation

For detailed usage instructions, command-line options, and troubleshooting:

- [CLI Version Documentation](README_CLI_VERSION.md)
- [Resource Graph Version Documentation](README_GRAPH_VERSION.md)

## License

This project is licensed under the MIT License - see the LICENSE file for details.
