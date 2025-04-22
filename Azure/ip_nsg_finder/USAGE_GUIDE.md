# IP-NSG-Finder: Usage Guide

## Overview

IP-NSG-Finder is a tool for analyzing Azure NSG (Network Security Group) flow logs to identify traffic patterns for IP addresses. The tool can filter traffic based on different criteria and process multiple IPs simultaneously from an Excel file. Results can be merged into a single report for easier analysis.

## Prerequisites and Installation

### 1. Azure CLI Installation and Setup

This tool requires Azure CLI to be installed and configured:

1. **Install Azure CLI**:
   - Windows: Download and run the installer from [Microsoft's official site](https://docs.microsoft.com/en-us/cli/azure/install-azure-cli-windows)
   - macOS: `brew install azure-cli`
   - Linux: Follow [distribution-specific instructions](https://docs.microsoft.com/en-us/cli/azure/install-azure-cli-linux)

2. **Log in to Azure**:
   ```bash
   az login
   ```
   This will open a browser window for authentication. Follow the prompts to complete the login.

3. **Select your subscription** (if you have multiple):
   ```bash
   az account set --subscription "Your Subscription Name"
   ```

4. **Install the Resource Graph Extension** (required for efficient NSG searches):
   ```bash
   az extension add --name resource-graph
   ```

### 2. Python Dependencies

Ensure you have Python 3.6+ installed, then install the required dependencies:

```bash
pip install -r requirements.txt
```

The required packages include:
- pandas: For data processing and Excel file operations
- openpyxl: For Excel file handling
- ipaddress: For IP address validation and operations
- python-dateutil: For date/time handling

## Basic Usage

The tool now supports both single IP analysis and batch processing from Excel files.

### Single IP Analysis

```bash
python -m ip_nsg_finder.main --ip <target_ip> [options]
```

### Batch Processing from Excel

```bash
python -m ip_nsg_finder.main --excel <excel_file_path> [options]
```

### Parameters

#### Main Parameters
- `--ip` or `-i`: Target IP address to analyze
- `--excel` or `-e`: Excel file containing IP addresses to process

#### Optional Parameters
- `--time-range` or `-t`: Time range in hours to search (default: 24)
- `--verbose` or `-v`: Enable verbose output
- `--query-type`: Specify the type of traffic to analyze (standard, internet, intranet, noninternet_nonintranet)
- `--individual-results`: Save individual Excel files for each IP (by default, only merged results are saved)

## Query Types Explained

The tool offers several query types to filter network traffic in different ways:

### 1. Standard Query (`--query-type standard`)

**Description**: Returns all traffic flows associated with the target IP without any specific traffic type filtering.

**When to use**: When you want a comprehensive view of all traffic for an IP address.

**Logic**:
- Filters only by time range and target IP
- No additional filtering based on IP ranges
- Shows all traffic regardless of whether it's internal or external

**Example**:
```bash
python -m ip_nsg_finder.main --ip 10.1.2.3 --query-type standard
```

### 2. Internet Traffic Query (`--query-type internet`)

**Description**: Only shows traffic where the source or destination is outside your defined VNet ranges.

**When to use**: When you want to analyze communication with external/public IPs.

**Logic**:
- Excludes flows where either source or destination IP is in VNetRanges
- Excludes flows where either source or destination IP is in InternalExceptionRanges
- Requires presence of public IP information (SrcPublicIPs_s or DestPublicIPs_s)
- Extracts and cleans public IP addresses for easier analysis

**Example**:
```bash
python -m ip_nsg_finder.main --ip 10.1.2.3 --query-type internet
```

### 3. Intranet Traffic Query (`--query-type intranet`)

**Description**: Only shows traffic where both source and destination are within your defined VNet ranges.

**When to use**: When you want to analyze internal network communication.

**Logic**:
- Requires both source and destination IPs to be within VNetRanges
- VNetRanges must contain values for this query to return results
- Creates a summary with port usage and flow statistics

**Example**:
```bash
python -m ip_nsg_finder.main --ip 10.1.2.3 --query-type intranet
```

### 4. Edge Cases Traffic Query (`--query-type noninternet_nonintranet`)

**Description**: Shows special traffic patterns that don't fit cleanly into either internet or intranet categories.

**When to use**: When you need to analyze edge cases like connections to special external services that should be treated differently.

**Logic**:
- Source IP must be within VNetRanges
- Destination IP must either:
  - Be in VNetRanges but NOT in InternalExceptionRanges, OR
  - Be in InternalExceptionRanges 
- If InternalExceptionRanges is empty, behavior becomes similar to intranet query
- Creates a summary with port usage and flow statistics

**Example**:
```bash
python -m ip_nsg_finder.main --ip 10.1.2.3 --query-type noninternet_nonintranet
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
