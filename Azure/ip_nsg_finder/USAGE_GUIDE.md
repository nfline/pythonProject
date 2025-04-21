# IP-NSG-Finder: Usage Guide

## Overview

IP-NSG-Finder is a tool for analyzing Azure NSG (Network Security Group) flow logs to identify traffic patterns for a specific IP address. The tool can filter traffic based on different criteria, helping you understand network communications more effectively.

## Installation

Ensure you have Python 3.6+ installed, then install the required dependencies:

```bash
pip install -r requirements.txt
```

## Basic Usage

The basic command syntax is:

```bash
python -m ip_nsg_finder.main --ip <target_ip> [options]
```

### Required Parameters

- `--ip` or `-i`: Target IP address to analyze

### Optional Parameters

- `--time-range` or `-t`: Time range in hours to search (default: 24)
- `--verbose` or `-v`: Enable verbose output
- `--query-type`: Specify the type of traffic to analyze (standard, internet, intranet, noninternet_nonintranet)

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

## Troubleshooting

- If no results appear, check that your time range is appropriate
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
