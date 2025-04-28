# IP-NSG-Finder: Quick Reference Guide

## Overview

IP-NSG-Finder analyzes Azure NSG flow logs to identify traffic patterns for IP addresses. It filters traffic by criteria and processes multiple IPs from Excel files, consolidating results into a single report.

## Setup Guide

### 1. Prerequisites

- **Azure CLI**: 
  ```bash
  # Windows: Install from Microsoft's website
  # macOS: brew install azure-cli
  # Linux: Follow distribution-specific instructions
  
  # Login to Azure
  az login
  
  # Set subscription (if needed)
  az account set --subscription "Your Subscription Name"
  
  # Install Resource Graph extension
  az extension add --name resource-graph
  ```

- **Python Dependencies**:
  ```bash
  pip install -r requirements.txt
  # Installs: pandas, openpyxl, ipaddress, python-dateutil
  ```

### 2. Basic Commands

| Operation | Command |
|-----------|---------|
| Single IP | `python -m ip_nsg_finder.main --ip <target_ip> [options]` |
| Batch Mode | `python -m ip_nsg_finder.main --excel <file_path> [options]` |

### 3. Key Parameters

- **Required**: Either `--ip/-i` (target IP) or `--excel/-e` (Excel file)
- **Optional**:
  - `--time-range/-t`: Search period in hours (default: 24)
  - `--verbose/-v`: Detailed output
  - `--query-type`: Traffic filter (standard, internet, intranet, noninternet_nonintranet)
  - `--individual-results`: Save per-IP Excel files

## Excel Usage Guide

### 1. Excel File Format

Create an Excel file with the following structure:
- First column: IP addresses to analyze
- Header row required (any name works)

Example:
| IP Address |
|------------|
| 10.1.2.3   |
| 192.168.1.1|
| 172.16.5.10|

### 2. Running with Excel Input

```bash
# Basic Excel processing
python -m ip_nsg_finder.main --excel path/to/ips.xlsx

# With additional options
python -m ip_nsg_finder.main --excel path/to/ips.xlsx --query-type internet --time-range 48
```

### 3. Excel Output

The tool generates Excel reports in the `report` directory:
- For batch processing: A merged report with all IPs
- With `--individual-results`: Individual reports in `report/individual/`

Output columns include:
- Source/Destination IPs
- Public IPs involved
- NSG name and rules
- Flow direction and status
- Ports and protocols

## Query Types

1. **Standard**: All traffic for the IP
   ```bash
   python -m ip_nsg_finder.main --excel ips.xlsx --query-type standard
   ```

2. **Internet**: Only external traffic
   ```bash
   python -m ip_nsg_finder.main --excel ips.xlsx --query-type internet
   ```

3. **Intranet**: Only internal network traffic
   ```bash
   python -m ip_nsg_finder.main --excel ips.xlsx --query-type intranet
   ```

4. **Edge Cases**: Special traffic patterns
   ```bash
   python -m ip_nsg_finder.main --excel ips.xlsx --query-type noninternet_nonintranet
   ```

## Configuration

### VNet Ranges

The tool uses predefined VNet ranges to determine what constitutes internal network traffic. By default, these include:
- 10.0.0.0/8
- 172.16.0.0/12
- 192.168.0.0/16

You can modify these ranges in the `kql_query.py` file to match your organization's network architecture.

### Internal Exception Ranges

Internal Exception Ranges are special public IP ranges that you want to treat differently from regular public IPs. These are used in the "Edge Cases" query.

## Output

Results are saved in two formats:
1. JSON format with raw query results
2. Excel spreadsheet for easier analysis

The output files are created in an `output` directory with timestamps and target IP in the filename.

## Query Logic Details

### IP Classification Strategy

- **Standard IPs**: Raw IPs from the flow logs (SrcIP_s, DestIP_s)
- **Public IPs**: Extracted from SrcPublicIPs_s and DestPublicIPs_s fields
- **Clean IPs**: Further processed to extract just valid IP addresses

### VNet Range Logic

When an IP is checked against VNetRanges:
- If the IP is within any CIDR range defined in VNetRanges, it's considered internal
- This applies to both regular IPs and public IPs in the flow logs
- Adding a public IP range to VNetRanges will cause that range to be treated as internal

### Flow Filtering Logic

Different queries apply different filtering logic:
- Internet query: Excludes VNet and Exception ranges
- Intranet query: Requires both IPs to be in VNet ranges
- Edge Cases: Complex filtering based on combinations of ranges

## Directory Structure

The tool organizes output files in the following structure:

```
<current_working_directory>/
├── report/               # All Excel report files
│   └── individual/       # (Created only when using --individual-results)
│
└── log/                 # Logs and temporary files
    ├── app/             # Application logs
    └── temp/            # Temporary files (queries, JSON results)
```

## Excel Batch Processing

When using the `--excel` parameter, the tool:

1. Reads IP addresses from the specified Excel file (automatically detects columns containing IPs)
2. Processes each IP address using the specified query type
3. Merges results from all IPs into a single Excel file, sorted by time
4. Creates summary sheets showing traffic counts by IP and NSG

By default, individual Excel files for each IP are not saved. Use the `--individual-results` flag if you need separate files.

## Troubleshooting

- If no results appear, check that your time range is appropriate
- For Excel batch processing, ensure your Excel file has a column containing IP addresses
- The __pycache__ directory created by Python can be safely deleted if needed
- Verify that VNetRanges includes your organization's internal IP ranges
- For Intranet queries, ensure VNetRanges is not empty
- For Edge Cases queries with empty InternalExceptionRanges, results may overlap with Intranet query

## Examples

### Find All Internet Traffic for an IP in the Last 48 Hours

```bash
python -m ip_nsg_finder.main --ip 10.1.2.3 --query-type internet --time-range 48
```

### Analyze Internal Traffic Only

```bash
python -m ip_nsg_finder.main --ip 10.1.2.3 --query-type intranet
```

### Get Comprehensive Traffic View with Verbose Logging

```bash
python -m ip_nsg_finder.main --ip 10.1.2.3 --query-type standard --verbose
```
