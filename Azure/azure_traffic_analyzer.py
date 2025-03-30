#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Azure Network Traffic Analyzer

This script uses Azure CLI to retrieve network traffic information for specified IP addresses or subnets,
and exports the data to Excel format. It includes information such as source/destination addresses,
ports, protocols, action, traffic bytes, and timestamps.
"""

import os
import sys
import json
import argparse
import subprocess
from datetime import datetime, timedelta
from tqdm import tqdm
import pandas as pd
from pathlib import Path
import ipaddress

# Configure argument parser
def parse_arguments():
    parser = argparse.ArgumentParser(description='Analyze Azure Network Traffic and export to Excel')
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--resource-group', '-g', help='Azure Resource Group')
    group.add_argument('--all-resource-groups', '-a', action='store_true', help='Scan all accessible resource groups')
    group.add_argument('--discover-resource-group', '-d', action='store_true', help='Automatically discover resource group for the given IP or devices')
    parser.add_argument('--ip', help='IP address to filter results')
    parser.add_argument('--subnet', help='Subnet in CIDR notation (e.g., 10.0.0.0/24) to filter results')
    parser.add_argument('--nsg', help='Network Security Group name')
    parser.add_argument('--days', type=int, default=1, help='Number of days to look back (default: 1)')
    parser.add_argument('--hours', type=int, default=0, help='Number of hours to look back (default: 0)')
    parser.add_argument('--output', '-o', default='azure_traffic_data.xlsx', help='Output Excel file path')
    parser.add_argument('--devices-file', '-df', help='Excel file containing device names and IP addresses')
    parser.add_argument('--name-column', default='name', help='Column name for device names in the Excel file (default: name)')
    parser.add_argument('--ip-column', default='ipaddr', help='Column name for IP addresses in the Excel file (default: ipaddr)')
    parser.add_argument('--max-resource-groups', type=int, default=5, help='Maximum number of resource groups to scan when auto-discovering (default: 5)')
    
    return parser.parse_args()

# Check if Azure CLI is installed and logged in
def check_azure_cli():
    try:
        # Check if Azure CLI is installed
        result = subprocess.run(['az', '--version'], capture_output=True, text=True)
        if result.returncode != 0:
            print("Error: Azure CLI is not installed or not in PATH.")
            print("Please install Azure CLI: https://docs.microsoft.com/en-us/cli/azure/install-azure-cli")
            sys.exit(1)
        
        # Check if user is logged in
        result = subprocess.run(['az', 'account', 'show'], capture_output=True, text=True)
        if result.returncode != 0:
            print("Error: Not logged in to Azure CLI.")
            print("Please login using: az login")
            sys.exit(1)
            
        print("Azure CLI check passed. You are logged in.")
    except Exception as e:
        print(f"Error checking Azure CLI: {str(e)}")
        sys.exit(1)

# Get all accessible resource groups
def get_all_resource_groups():
    try:
        print("Retrieving all accessible resource groups...")
        cmd = ['az', 'group', 'list', '--query', '[].name', '--output', 'tsv']
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        if result.returncode != 0:
            print(f"Error retrieving resource groups: {result.stderr}")
            return []
        
        resource_groups = [rg.strip() for rg in result.stdout.strip().split('\n') if rg.strip()]
        print(f"Found {len(resource_groups)} accessible resource groups")
        return resource_groups
    except Exception as e:
        print(f"Error retrieving resource groups: {str(e)}")
        return []

# Find resource group(s) by IP address
def find_resource_group_by_ip(ip_address):
    try:
        print(f"Searching for resource group containing IP: {ip_address}...")
        cmd = ['az', 'network', 'nic', 'list', 
               '--query', f"[?ipConfigurations[0].privateIPAddress=='{ip_address}'].resourceGroup", 
               '--output', 'tsv']
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        if result.returncode != 0:
            print(f"Error searching for IP: {result.stderr}")
            return []
        
        resource_groups = [rg.strip() for rg in result.stdout.strip().split('\n') if rg.strip()]
        if resource_groups:
            print(f"Found IP {ip_address} in resource group(s): {', '.join(resource_groups)}")
        else:
            print(f"Could not find resource group for IP: {ip_address}")
        
        return resource_groups
    except Exception as e:
        print(f"Error searching for IP's resource group: {str(e)}")
        return []

# Find resource groups for multiple devices
def find_resource_groups_for_devices(devices, max_groups=5):
    resource_groups = set()
    
    print(f"Searching for resource groups for {len(devices)} devices...")
    for device in tqdm(devices, desc="Finding resource groups"):
        ip = device['ip']
        groups = find_resource_group_by_ip(ip)
        resource_groups.update(groups)
        
        # Limit the number of resource groups to avoid excessive scanning
        if len(resource_groups) >= max_groups:
            print(f"Reached maximum number of resource groups ({max_groups}). Limiting scan.")
            break
    
    return list(resource_groups)

# Load devices from Excel file
def load_devices_from_excel(file_path, name_column='name', ip_column='ipaddr'):
    try:
        print(f"Loading devices from {file_path}...")
        df = pd.read_excel(file_path)
        
        # Validate required columns exist
        if name_column not in df.columns or ip_column not in df.columns:
            print(f"Error: Required columns '{name_column}' and/or '{ip_column}' not found in the Excel file.")
            print(f"Available columns: {', '.join(df.columns)}")
            return []
        
        # Extract device information
        devices = []
        for _, row in df.iterrows():
            device_name = str(row[name_column])
            ip_address = str(row[ip_column])
            
            # Skip rows with empty values
            if pd.isna(device_name) or pd.isna(ip_address) or not device_name or not ip_address:
                continue
                
            devices.append({
                'name': device_name,
                'ip': ip_address
            })
        
        print(f"Successfully loaded {len(devices)} devices from Excel file")
        return devices
    except Exception as e:
        print(f"Error loading devices from Excel: {str(e)}")
        return []

# Get Network Security Groups
def get_network_security_groups(resource_group, nsg_name=None):
    cmd = ['az', 'network', 'nsg', 'list', '--resource-group', resource_group]
    if nsg_name:
        cmd = ['az', 'network', 'nsg', 'show', '--resource-group', resource_group, '--name', nsg_name]
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode != 0:
            print(f"Error retrieving Network Security Groups: {result.stderr}")
            return []
        
        data = json.loads(result.stdout)
        if nsg_name:
            return [data] if data else []
        return data
    except Exception as e:
        print(f"Error retrieving Network Security Groups: {str(e)}")
        return []

# Enable flow logs if not already enabled
def enable_flow_logs(resource_group, nsg_id, nsg_name):
    # Check if flow logs are already enabled for this NSG
    check_cmd = [
        'az', 'network', 'watcher', 'flow-log', 'show',
        '--resource-group', resource_group,
        '--nsg', nsg_id,
    ]
    
    try:
        result = subprocess.run(check_cmd, capture_output=True, text=True)
        if result.returncode == 0 and json.loads(result.stdout):
            print(f"Flow logs already enabled for NSG: {nsg_name}")
            return True
    except Exception:
        pass  # If any error occurs, we'll try to enable flow logs
    
    # Create storage account for flow logs if not exists
    storage_account_name = f"nsgflowlogs{abs(hash(nsg_name)) % 1000000:06d}"
    
    print(f"Creating/checking storage account {storage_account_name} for flow logs...")
    
    # Check if storage account exists
    storage_cmd = [
        'az', 'storage', 'account', 'show',
        '--name', storage_account_name,
        '--resource-group', resource_group
    ]
    
    result = subprocess.run(storage_cmd, capture_output=True, text=True)
    if result.returncode != 0:
        # Create storage account
        create_storage_cmd = [
            'az', 'storage', 'account', 'create',
            '--name', storage_account_name,
            '--resource-group', resource_group,
            '--kind', 'StorageV2',
            '--sku', 'Standard_LRS'
        ]
        
        print(f"Creating storage account: {storage_account_name}")
        result = subprocess.run(create_storage_cmd, capture_output=True, text=True)
        if result.returncode != 0:
            print(f"Error creating storage account: {result.stderr}")
            return False
    
    # Get Network Watcher in the NSG's region
    location_cmd = [
        'az', 'network', 'nsg', 'show',
        '--resource-group', resource_group,
        '--name', nsg_name,
        '--query', 'location',
        '--output', 'tsv'
    ]
    
    result = subprocess.run(location_cmd, capture_output=True, text=True)
    if result.returncode != 0:
        print(f"Error getting NSG location: {result.stderr}")
        return False
    
    location = result.stdout.strip()
    
    # Enable Network Watcher if not enabled
    watcher_cmd = [
        'az', 'network', 'watcher', 'configure',
        '--resource-group', resource_group,
        '--locations', location,
        '--enabled', 'true'
    ]
    
    result = subprocess.run(watcher_cmd, capture_output=True, text=True)
    if result.returncode != 0:
        print(f"Error configuring Network Watcher: {result.stderr}")
        return False
    
    # Enable flow logs
    enable_cmd = [
        'az', 'network', 'watcher', 'flow-log', 'create',
        '--resource-group', resource_group,
        '--nsg', nsg_id,
        '--storage-account', storage_account_name,
        '--enabled', 'true',
        '--retention', '2',
        '--format', 'JSON'
    ]
    
    print(f"Enabling flow logs for NSG: {nsg_name}")
    result = subprocess.run(enable_cmd, capture_output=True, text=True)
    if result.returncode != 0:
        print(f"Error enabling flow logs: {result.stderr}")
        return False
    
    print(f"Flow logs enabled for NSG: {nsg_name}")
    return True

# Get flow log data
def get_flow_log_data(resource_group, nsg_id, nsg_name, start_time, end_time):
    # Format the times as required by Azure CLI
    start_time_str = start_time.strftime('%Y-%m-%dT%H:%M:%SZ')
    end_time_str = end_time.strftime('%Y-%m-%dT%H:%M:%SZ')
    
    cmd = [
        'az', 'network', 'watcher', 'flow-log', 'show-data',
        '--resource-group', resource_group,
        '--nsg', nsg_id,
        '--start-time', start_time_str,
        '--end-time', end_time_str
    ]
    
    print(f"Retrieving flow log data for NSG: {nsg_name}")
    print(f"Time range: {start_time_str} to {end_time_str}")
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode != 0:
            print(f"Error retrieving flow log data: {result.stderr}")
            return []
        
        data = json.loads(result.stdout)
        return data.get('records', [])
    except Exception as e:
        print(f"Error retrieving flow log data: {str(e)}")
        return []

# Filter flow log records by IP or subnet
def filter_records(records, ip=None, subnet=None):
    if not ip and not subnet:
        return records
    
    filtered_records = []
    
    for record in records:
        flows = record.get('properties', {}).get('flows', [])
        filtered_flows = []
        
        for flow in flows:
            flow_tuples = flow.get('flowTuples', [])
            filtered_tuples = []
            
            for tuple_str in flow_tuples:
                parts = tuple_str.split(',')
                if len(parts) < 7:
                    continue
                
                source_ip = parts[1]
                dest_ip = parts[2]
                
                if ip and (ip == source_ip or ip == dest_ip):
                    filtered_tuples.append(tuple_str)
                elif subnet:
                    # Proper CIDR check using ipaddress module
                    try:
                        subnet_net = ipaddress.IPv4Network(subnet)
                        source_in_subnet = ipaddress.IPv4Address(source_ip) in subnet_net
                        dest_in_subnet = ipaddress.IPv4Address(dest_ip) in subnet_net
                        
                        if source_in_subnet or dest_in_subnet:
                            filtered_tuples.append(tuple_str)
                    except ValueError:
                        # Handle invalid IP or subnet format
                        continue
            
            if filtered_tuples:
                new_flow = flow.copy()
                new_flow['flowTuples'] = filtered_tuples
                filtered_flows.append(new_flow)
        
        if filtered_flows:
            new_record = record.copy()
            new_record['properties']['flows'] = filtered_flows
            filtered_records.append(new_record)
    
    return filtered_records

# Parse flow logs into a structured format for Excel
def parse_flow_logs(records, device_name=None):
    data = []
    
    for record in records:
        mac_address_table = record.get('properties', {}).get('macAddress', {})
        flows = record.get('properties', {}).get('flows', [])
        
        for flow in flows:
            rule = flow.get('rule')
            flow_tuples = flow.get('flowTuples', [])
            
            for tuple_str in flow_tuples:
                parts = tuple_str.split(',')
                if len(parts) < 7:
                    continue
                
                timestamp_unix = int(parts[0])
                timestamp = datetime.utcfromtimestamp(timestamp_unix).strftime('%Y-%m-%d %H:%M:%S')
                source_ip = parts[1]
                dest_ip = parts[2]
                source_port = parts[3]
                dest_port = parts[4]
                protocol = 'TCP' if parts[5] == 'T' else 'UDP' if parts[5] == 'U' else parts[5]
                direction = 'Inbound' if parts[6] == 'I' else 'Outbound' if parts[6] == 'O' else parts[6]
                action = 'Allow' if parts[7] == 'A' else 'Deny' if parts[7] == 'D' else parts[7]
                
                # Traffic bytes might be in different positions depending on the flow log format version
                traffic_bytes = int(parts[8]) if len(parts) > 8 else 0
                
                entry = {
                    'timestamp': timestamp,
                    'source_ip': source_ip,
                    'source_port': source_port,
                    'destination_ip': dest_ip,
                    'destination_port': dest_port,
                    'protocol': protocol,
                    'direction': direction,
                    'action': action,
                    'traffic_bytes': traffic_bytes,
                    'rule': rule
                }
                
                # Add device name if provided
                if device_name:
                    entry['device_name'] = device_name
                    
                data.append(entry)
    
    return data

# Export data to Excel
def export_to_excel(data, output_file):
    if not data:
        print("No data to export.")
        return False
    
    try:
        df = pd.DataFrame(data)
        
        # Reorder columns for better readability
        columns = []
        
        # Put device_name first if it exists
        if 'device_name' in df.columns:
            columns.append('device_name')
            
        columns.extend([
            'timestamp', 'source_ip', 'source_port', 'destination_ip', 'destination_port',
            'protocol', 'direction', 'action', 'traffic_bytes', 'rule'
        ])
        
        # Filter to only include columns that exist in the dataframe
        columns = [col for col in columns if col in df.columns]
        df = df[columns]
        
        # Create output directory if it doesn't exist
        output_path = Path(output_file)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Export to Excel
        print(f"Exporting data to {output_file}...")
        
        # Create Excel writer
        with pd.ExcelWriter(output_file, engine='openpyxl') as writer:
            # Create summary sheet
            if 'device_name' in df.columns:
                # Create a summary by device
                device_summary = df.groupby('device_name').agg({
                    'traffic_bytes': 'sum',
                    'protocol': 'count'  # Count of records
                }).reset_index()
                device_summary.columns = ['Device Name', 'Total Traffic (bytes)', 'Connection Count']
                
                # Add this summary as the first sheet
                device_summary.to_excel(writer, sheet_name='Device Summary', index=False)
                
                # Create a sheet for each device
                for device in df['device_name'].unique():
                    device_data = df[df['device_name'] == device]
                    sheet_name = device[:31]  # Excel sheet names are limited to 31 characters
                    device_data.to_excel(writer, sheet_name=sheet_name, index=False)
            
            # Add all data to a 'All Traffic' sheet
            df.to_excel(writer, sheet_name='All Traffic', index=False)
        
        # Apply some basic Excel formatting
        with pd.ExcelWriter(output_file, engine='openpyxl', mode='a') as writer:
            workbook = writer.book
            for worksheet_name in workbook.sheetnames:
                worksheet = workbook[worksheet_name]
                # Set column widths
                for i, column in enumerate(worksheet[1]):
                    # Apply width based on column content
                    max_length = 0
                    column_name = column.value
                    if column_name:
                        max_length = max(max_length, len(str(column_name)))
                    
                    # Check data in the column (only first 100 rows for performance)
                    for cell in worksheet[column.column_letter + '2':column.column_letter + '100']:
                        if cell.value:
                            max_length = max(max_length, len(str(cell.value)))
                    
                    # Set column width (add some padding)
                    adjusted_width = max_length + 2
                    worksheet.column_dimensions[column.column_letter].width = min(adjusted_width, 30)
        
        print(f"Successfully exported {len(data)} records to {output_file}")
        return True
    except Exception as e:
        print(f"Error exporting data to Excel: {str(e)}")
        return False

# Process a single device
def process_device(device, resource_groups, nsgs_by_resource_group, start_time, end_time):
    device_name = device['name']
    device_ip = device['ip']
    
    print(f"\n=== Processing device: {device_name} (IP: {device_ip}) ===")
    
    all_device_records = []
    
    for resource_group, nsgs in nsgs_by_resource_group.items():
        print(f"Checking resource group: {resource_group} for traffic related to {device_name}")
        
        for nsg in nsgs:
            nsg_name = nsg.get('name')
            nsg_id = nsg.get('id')
            
            print(f"Checking NSG: {nsg_name} for traffic related to {device_name}")
            
            # Get flow log data
            records = get_flow_log_data(resource_group, nsg_id, nsg_name, start_time, end_time)
            if not records:
                print(f"No flow log data found for NSG: {nsg_name}")
                continue
            
            # Filter records for this device
            filtered_records = filter_records(records, ip=device_ip)
            if not filtered_records:
                print(f"No matching records for device {device_name} in NSG: {nsg_name}")
                continue
            
            print(f"Found traffic data for device {device_name} in NSG: {nsg_name}")
            all_device_records.extend(filtered_records)
    
    # Parse flow logs with device name
    return parse_flow_logs(all_device_records, device_name)

def main():
    args = parse_arguments()
    
    # Set up time range
    end_time = datetime.utcnow()
    start_time = end_time - timedelta(days=args.days, hours=args.hours)
    
    print(f"=== Azure Network Traffic Analyzer ===")
    print(f"Time Range: {args.days} days, {args.hours} hours (from {start_time} to {end_time})")
    
    # Check if Azure CLI is installed and user is logged in
    check_azure_cli()
    
    # Determine resource groups to process
    resource_groups = []
    
    if args.resource_group:
        resource_groups = [args.resource_group]
        print(f"Using specified resource group: {args.resource_group}")
    elif args.all_resource_groups:
        resource_groups = get_all_resource_groups()
        print(f"Using all {len(resource_groups)} accessible resource groups")
    elif args.discover_resource_group:
        # Auto-discover resource groups based on IP or devices
        if args.devices_file:
            devices = load_devices_from_excel(args.devices_file, args.name_column, args.ip_column)
            if not devices:
                print("No devices found in the Excel file or error loading file. Exiting.")
                return
            resource_groups = find_resource_groups_for_devices(devices, args.max_resource_groups)
        elif args.ip:
            resource_groups = find_resource_group_by_ip(args.ip)
        elif args.subnet:
            # For subnets, we might need to check all resource groups or limit to a reasonable number
            print("Auto-discovery for subnets is not precise. Using all accessible resource groups.")
            resource_groups = get_all_resource_groups()
            # Limit to reasonable number if too many
            if len(resource_groups) > args.max_resource_groups:
                print(f"Limiting to {args.max_resource_groups} resource groups for subnet scanning.")
                resource_groups = resource_groups[:args.max_resource_groups]
    
    if not resource_groups:
        print("No resource groups found or specified. Exiting.")
        return
    
    print(f"Processing {len(resource_groups)} resource group(s): {', '.join(resource_groups)}")
    
    # Get NSGs for all resource groups
    all_nsgs = {}
    for resource_group in resource_groups:
        nsgs = get_network_security_groups(resource_group, args.nsg)
        if nsgs:
            all_nsgs[resource_group] = nsgs
            print(f"Found {len(nsgs)} Network Security Group(s) in {resource_group}")
        else:
            print(f"No Network Security Groups found in {resource_group}")
    
    if not all_nsgs:
        print("No Network Security Groups found in any resource group. Exiting.")
        return
    
    # Enable flow logs for all NSGs in all resource groups
    for resource_group, nsgs in all_nsgs.items():
        for nsg in nsgs:
            nsg_name = nsg.get('name')
            nsg_id = nsg.get('id')
            enable_flow_logs(resource_group, nsg_id, nsg_name)
    
    all_data = []
    
    # If devices file is provided, process each device
    if args.devices_file:
        devices = load_devices_from_excel(args.devices_file, args.name_column, args.ip_column)
        if not devices:
            print("No devices found in the Excel file or error loading file. Exiting.")
            return
        
        # Process each device
        for device in tqdm(devices, desc="Processing devices"):
            device_data = process_device(device, resource_groups, all_nsgs, start_time, end_time)
            all_data.extend(device_data)
    else:
        # Process specific IP or subnet if provided
        if args.ip:
            print(f"Filtering for IP: {args.ip}")
        if args.subnet:
            print(f"Filtering for Subnet: {args.subnet}")
        
        all_records = []
        
        for resource_group, nsgs in all_nsgs.items():
            print(f"\nProcessing resource group: {resource_group}")
            
            for nsg in tqdm(nsgs, desc=f"Processing NSGs in {resource_group}"):
                nsg_name = nsg.get('name')
                nsg_id = nsg.get('id')
                
                print(f"\nProcessing NSG: {nsg_name}")
                
                # Get flow log data
                records = get_flow_log_data(resource_group, nsg_id, nsg_name, start_time, end_time)
                if not records:
                    print(f"No flow log data found for NSG: {nsg_name}")
                    continue
                
                print(f"Retrieved {len(records)} flow log records for NSG: {nsg_name}")
                
                # Filter records if needed
                filtered_records = filter_records(records, args.ip, args.subnet)
                if not filtered_records:
                    print(f"No matching records after filtering for NSG: {nsg_name}")
                    continue
                
                all_records.extend(filtered_records)
        
        if not all_records:
            print("No matching flow log records found across all resource groups and NSGs. Exiting.")
            return
        
        # Parse flow log data
        all_data = parse_flow_logs(all_records)
    
    if not all_data:
        print("No data to export after processing. Exiting.")
        return
    
    # Export to Excel
    export_to_excel(all_data, args.output)
    
    print("\nDone!")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nOperation cancelled by user.")
    except Exception as e:
        print(f"\nAn error occurred: {str(e)}")
