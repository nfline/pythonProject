#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Azure Network Traffic Analyzer (Resource Graph Version)

This script uses Azure Resource Graph API and Azure CLI to retrieve network traffic information 
for specified IP addresses or subnets across multiple subscriptions and resource groups,
and exports the data to Excel format. It includes information such as source/destination addresses,
ports, protocols, action, traffic bytes, and timestamps.
"""

import os
import sys
import json
import argparse
import subprocess
from datetime import datetime, timedelta, timezone
from tqdm import tqdm
import pandas as pd
from pathlib import Path
import ipaddress
import concurrent.futures
from azure.identity import DefaultAzureCredential
from azure.mgmt.resourcegraph import ResourceGraphClient
from azure.mgmt.resourcegraph.models import QueryRequest

# Check if required packages are installed
def check_dependencies():
    missing_packages = []
    
    # Check core packages
    try:
        import pandas
    except ImportError:
        missing_packages.append("pandas")
    
    try:
        import tqdm
    except ImportError:
        missing_packages.append("tqdm")
    
    try:
        import openpyxl
    except ImportError:
        missing_packages.append("openpyxl")
    
    try:
        import ipaddress
    except ImportError:
        missing_packages.append("ipaddress")
    
    # Check Azure packages
    try:
        from azure.identity import DefaultAzureCredential
    except ImportError:
        missing_packages.append("azure-identity")
    
    try:
        from azure.mgmt.resourcegraph import ResourceGraphClient
    except ImportError:
        missing_packages.append("azure-mgmt-resourcegraph")
    
    if missing_packages:
        print("Error: Missing required Python packages:")
        for pkg in missing_packages:
            print(f"  - {pkg}")
        print("\nPlease install the missing packages with:")
        print(f"pip install {' '.join(missing_packages)}")
        print("\nOr install all requirements with:")
        print("pip install -r requirements_graph.txt")
        return False
    
    return True

# Configure argument parser
def parse_arguments():
    parser = argparse.ArgumentParser(description='Analyze Azure Network Traffic using Resource Graph API and export to Excel')
    parser.add_argument('--ip', help='IP address to filter results')
    parser.add_argument('--subnet', help='Subnet in CIDR notation (e.g., 10.0.0.0/24) to filter results')
    parser.add_argument('--nsg', help='Network Security Group name (optional)')
    parser.add_argument('--subscription', '-s', help='Specific subscription ID (optional, omit to search all accessible subscriptions)')
    parser.add_argument('--resource-group', '-g', help='Specific resource group (optional, omit to search all accessible resource groups)')
    parser.add_argument('--days', type=int, default=1, help='Number of days to look back (default: 1)')
    parser.add_argument('--hours', type=int, default=0, help='Number of hours to look back (default: 0)')
    parser.add_argument('--output', '-o', default='azure_traffic_data.xlsx', help='Output Excel file path')
    parser.add_argument('--devices-file', '-df', help='Excel file containing device names and IP addresses')
    parser.add_argument('--name-column', default='name', help='Column name for device names in the Excel file (default: name)')
    parser.add_argument('--ip-column', default='ipaddr', help='Column name for IP addresses in the Excel file (default: ipaddr)')
    parser.add_argument('--max-concurrent', type=int, default=3, help='Maximum number of concurrent queries (default: 3)')
    parser.add_argument('--verbose', '-v', action='store_true', help='Enable verbose output')
    
    return parser.parse_args()

# Check if Azure CLI is installed and logged in
def check_azure_cli():
    try:
        # Try with standard command
        az_command = 'az'
        
        # On Windows, also check common installation paths if standard command fails
        if os.name == 'nt':  # Windows
            possible_paths = [
                r'C:\Program Files (x86)\Microsoft SDKs\Azure\CLI2\wbin\az.cmd',
                r'C:\Program Files\Microsoft SDKs\Azure\CLI2\wbin\az.cmd',
                os.path.expanduser(r'~\AppData\Local\Programs\Microsoft SDKs\Azure\CLI2\wbin\az.cmd'),
                # Add more potential paths if needed
            ]
            
            # Try standard command first
            try:
                result = subprocess.run([az_command, '--version'], capture_output=True, text=True)
                if result.returncode != 0:
                    raise Exception("Standard 'az' command failed")
            except Exception as e:
                # Try alternate paths
                found = False
                for path in possible_paths:
                    if os.path.exists(path):
                        az_command = path
                        found = True
                        print(f"Using Azure CLI at: {path}")
                        break
                
                if not found:
                    print("Error: Azure CLI is not installed or not in PATH.")
                    print("Please install Azure CLI: https://docs.microsoft.com/en-us/cli/azure/install-azure-cli")
                    print("Common installation paths checked:")
                    for path in possible_paths:
                        print(f"  - {path}")
                    print("\nIf Azure CLI is installed but in a different location, please add it to your PATH.")
                    sys.exit(1)
        
        # Check Azure CLI version
        result = subprocess.run([az_command, '--version'], capture_output=True, text=True)
        if result.returncode != 0:
            print("Error: Azure CLI check failed.")
            print(f"Command output: {result.stdout}")
            print(f"Command error: {result.stderr}")
            sys.exit(1)
        
        # Check if user is logged in
        result = subprocess.run([az_command, 'account', 'show'], capture_output=True, text=True)
        if result.returncode != 0:
            print("Error: Not logged in to Azure CLI.")
            print("Please login using: az login")
            sys.exit(1)
            
        print("Azure CLI check passed. You are logged in.")
    except Exception as e:
        print(f"Error checking Azure CLI: {str(e)}")
        print("\nPlease ensure Azure CLI is installed and accessible from the command line.")
        print("Installation guide: https://docs.microsoft.com/en-us/cli/azure/install-azure-cli")
        sys.exit(1)

# Get Azure subscription IDs
def get_subscriptions():
    # Global variable to store az command path
    global az_command
    
    try:
        print("Retrieving accessible subscriptions...")
        cmd = [az_command, 'account', 'list', '--query', '[].id', '--output', 'tsv']
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        if result.returncode != 0:
            print(f"Error retrieving subscriptions: {result.stderr}")
            return []
        
        subscriptions = [sub.strip() for sub in result.stdout.strip().split('\n') if sub.strip()]
        print(f"Found {len(subscriptions)} accessible subscriptions")
        return subscriptions
    except Exception as e:
        print(f"Error retrieving subscriptions: {str(e)}")
        return []

# Get Resource Graph client
def get_resource_graph_client():
    try:
        credential = DefaultAzureCredential()
        client = ResourceGraphClient(credential)
        return client
    except Exception as e:
        print(f"Error initializing Resource Graph client: {str(e)}")
        print("Ensure you have installed 'azure-identity' and 'azure-mgmt-resourcegraph' packages.")
        print("Run: pip install azure-identity azure-mgmt-resourcegraph")
        sys.exit(1)

# Find NSGs across subscriptions using Resource Graph
def find_nsgs(client, subscriptions, resource_group=None, nsg_name=None):
    query = "Resources | where type == 'microsoft.network/networksecuritygroups'"
    
    if resource_group:
        query += f" | where resourceGroup == '{resource_group}'"
    
    if nsg_name:
        query += f" | where name == '{nsg_name}'"
        
    query += " | project id, name, resourceGroup, subscriptionId, location"
    
    request = QueryRequest(
        subscriptions=subscriptions,
        query=query
    )
    
    try:
        response = client.resources(request)
        nsgs = []
        
        for nsg in response.data:
            nsgs.append({
                'id': nsg['id'],
                'name': nsg['name'],
                'resourceGroup': nsg['resourceGroup'],
                'subscriptionId': nsg['subscriptionId'],
                'location': nsg['location']
            })
        
        print(f"Found {len(nsgs)} Network Security Groups")
        return nsgs
    except Exception as e:
        print(f"Error finding NSGs: {str(e)}")
        return []

# Find network interfaces by IP address
def find_nics_by_ip(client, subscriptions, ip_address):
    query = f"Resources | where type == 'microsoft.network/networkinterfaces'"
    query += f" | where properties.ipConfigurations[0].properties.privateIPAddress == '{ip_address}'"
    query += " | project id, name, resourceGroup, subscriptionId, properties.ipConfigurations[0].properties.privateIPAddress"
    
    request = QueryRequest(
        subscriptions=subscriptions,
        query=query
    )
    
    try:
        response = client.resources(request)
        nics = []
        
        for nic in response.data:
            nics.append({
                'id': nic['id'],
                'name': nic['name'],
                'resourceGroup': nic['resourceGroup'],
                'subscriptionId': nic['subscriptionId'],
                'ipAddress': nic['properties_ipConfigurations_0_properties_privateIPAddress']
            })
        
        if nics:
            print(f"Found IP {ip_address} in {len(nics)} network interfaces")
        else:
            print(f"IP {ip_address} not found in any network interface")
            
        return nics
    except Exception as e:
        print(f"Error finding network interfaces: {str(e)}")
        return []

# Find virtual machines in subnet
def find_vms_in_subnet(client, subscriptions, subnet):
    try:
        subnet_network = ipaddress.IPv4Network(subnet)
        start_ip = str(subnet_network[0])
        end_ip = str(subnet_network[-1])
        
        # Resource Graph doesn't support direct CIDR matching, using IP range instead
        # This is a simplified approach and may not catch all VMs in the subnet
        query = f"Resources | where type == 'microsoft.network/networkinterfaces'"
        query += " | extend ipAddress = properties.ipConfigurations[0].properties.privateIPAddress"
        query += f" | where ipAddress >= '{start_ip}' and ipAddress <= '{end_ip}'"
        query += " | project id, name, resourceGroup, subscriptionId, ipAddress"
        
        request = QueryRequest(
            subscriptions=subscriptions,
            query=query
        )
        
        response = client.resources(request)
        vms = []
        
        for vm in response.data:
            # Double-check the IP is actually in the subnet (the query is an approximation)
            try:
                ip = ipaddress.IPv4Address(vm['ipAddress'])
                if ip in subnet_network:
                    vms.append({
                        'id': vm['id'],
                        'name': vm['name'],
                        'resourceGroup': vm['resourceGroup'],
                        'subscriptionId': vm['subscriptionId'],
                        'ipAddress': vm['ipAddress']
                    })
            except:
                continue
        
        print(f"Found {len(vms)} virtual machines in subnet {subnet}")
        return vms
    except Exception as e:
        print(f"Error finding VMs in subnet: {str(e)}")
        return []

# Enable flow logs if not already enabled
def enable_flow_logs(nsg):
    # Global variable to store az command path
    global az_command
    
    resource_group = nsg['resourceGroup']
    nsg_id = nsg['id']
    nsg_name = nsg['name']
    subscription_id = nsg['subscriptionId']
    
    # Set current subscription context
    set_subscription_cmd = [
        az_command, 'account', 'set', 
        '--subscription', subscription_id
    ]
    
    try:
        result = subprocess.run(set_subscription_cmd, capture_output=True, text=True)
        if result.returncode != 0:
            print(f"Error setting subscription context: {result.stderr}")
            return False
    except Exception as e:
        print(f"Error setting subscription context: {str(e)}")
        return False
        
    # Check if flow logs are already enabled for this NSG
    check_cmd = [
        az_command, 'network', 'watcher', 'flow-log', 'show',
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
        az_command, 'storage', 'account', 'show',
        '--name', storage_account_name,
        '--resource-group', resource_group
    ]
    
    result = subprocess.run(storage_cmd, capture_output=True, text=True)
    if result.returncode != 0:
        # Create storage account
        create_storage_cmd = [
            az_command, 'storage', 'account', 'create',
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
    
    # Get location from NSG
    location = nsg['location']
    
    # Enable Network Watcher if not enabled
    watcher_cmd = [
        az_command, 'network', 'watcher', 'configure',
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
        az_command, 'network', 'watcher', 'flow-log', 'create',
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

# Get flow log data with subscription context
def get_flow_log_data(nsg, start_time, end_time):
    # Global variable to store az command path
    global az_command
    
    resource_group = nsg['resourceGroup']
    nsg_id = nsg['id']
    nsg_name = nsg['name']
    subscription_id = nsg['subscriptionId']
    
    # Set current subscription context
    set_subscription_cmd = [
        az_command, 'account', 'set', 
        '--subscription', subscription_id
    ]
    
    try:
        result = subprocess.run(set_subscription_cmd, capture_output=True, text=True)
        if result.returncode != 0:
            print(f"Error setting subscription context: {result.stderr}")
            return []
    except Exception as e:
        print(f"Error setting subscription context: {str(e)}")
        return []
    
    # Format the times as required by Azure CLI (ISO format with Z suffix for UTC)
    start_time_str = start_time.strftime('%Y-%m-%dT%H:%M:%SZ')
    end_time_str = end_time.strftime('%Y-%m-%dT%H:%M:%SZ')
    
    cmd = [
        az_command, 'network', 'watcher', 'flow-log', 'show-data',
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
                # Use timezone-aware datetime
                timestamp = datetime.fromtimestamp(timestamp_unix, tz=timezone.utc).strftime('%Y-%m-%d %H:%M:%S')
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

# Process a single device with multi-subscription support
def process_device(device, nsgs, start_time, end_time, max_concurrent=3):
    device_name = device['name']
    device_ip = device['ip']
    
    print(f"\n=== Processing device: {device_name} (IP: {device_ip}) ===")
    
    all_device_records = []
    
    # Use ThreadPoolExecutor to parallelize NSG queries
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_concurrent) as executor:
        future_to_nsg = {
            executor.submit(get_flow_log_data, nsg, start_time, end_time): nsg
            for nsg in nsgs
        }
        
        for future in tqdm(concurrent.futures.as_completed(future_to_nsg), total=len(nsgs), desc=f"Processing NSGs for {device_name}"):
            nsg = future_to_nsg[future]
            try:
                records = future.result()
                if not records:
                    continue
                
                # Filter records for this device
                filtered_records = filter_records(records, ip=device_ip)
                if filtered_records:
                    print(f"Found traffic data for device {device_name} in NSG: {nsg['name']}")
                    all_device_records.extend(filtered_records)
            except Exception as e:
                print(f"Error processing NSG {nsg['name']}: {str(e)}")
    
    # Parse flow logs with device name
    return parse_flow_logs(all_device_records, device_name)

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

def main():
    # Initialize global variable for az command
    global az_command
    az_command = 'az'  # Default value
    
    args = parse_arguments()
    
    # Check required dependencies
    if not check_dependencies():
        sys.exit(1)
    
    # Set up time range using timezone-aware objects
    end_time = datetime.now(timezone.utc)
    start_time = end_time - timedelta(days=args.days, hours=args.hours)
    
    print(f"=== Azure Network Traffic Analyzer (Resource Graph Version) ===")
    print(f"Time Range: {args.days} days, {args.hours} hours (from {start_time} to {end_time})")
    
    # Check if Azure CLI is installed and user is logged in
    check_azure_cli()
    
    # Get subscriptions
    subscriptions = []
    if args.subscription:
        subscriptions = [args.subscription]
        print(f"Using specified subscription: {args.subscription}")
    else:
        subscriptions = get_subscriptions()
        if not subscriptions:
            print("No accessible subscriptions found. Please check your Azure credentials.")
            return
    
    # Initialize Resource Graph client
    graph_client = get_resource_graph_client()
    
    # Get NSGs based on parameters
    print("\nFinding Network Security Groups...")
    nsgs = find_nsgs(graph_client, subscriptions, args.resource_group, args.nsg)
    
    if not nsgs:
        print("No Network Security Groups found. Exiting.")
        return
    
    # Enable flow logs for all NSGs
    print("\nEnsuring flow logs are enabled...")
    for nsg in tqdm(nsgs, desc="Enabling flow logs"):
        enable_flow_logs(nsg)
    
    # For IP or subnet filtering, find related resources
    ip_resources = []
    if args.ip and not args.devices_file:
        print(f"\nFinding resources with IP: {args.ip}")
        ip_resources = find_nics_by_ip(graph_client, subscriptions, args.ip)
    
    subnet_resources = []
    if args.subnet and not args.devices_file:
        print(f"\nFinding resources in subnet: {args.subnet}")
        subnet_resources = find_vms_in_subnet(graph_client, subscriptions, args.subnet)
    
    all_data = []
    
    # If devices file is provided, process each device
    if args.devices_file:
        devices = load_devices_from_excel(args.devices_file, args.name_column, args.ip_column)
        if not devices:
            print("No devices found in the Excel file or error loading file. Exiting.")
            return
        
        # Process each device
        for device in tqdm(devices, desc="Processing devices"):
            device_data = process_device(device, nsgs, start_time, end_time, args.max_concurrent)
            all_data.extend(device_data)
    else:
        # Process flow logs for all NSGs
        all_records = []
        
        # Use ThreadPoolExecutor to parallelize NSG queries
        with concurrent.futures.ThreadPoolExecutor(max_workers=args.max_concurrent) as executor:
            future_to_nsg = {
                executor.submit(get_flow_log_data, nsg, start_time, end_time): nsg
                for nsg in nsgs
            }
            
            for future in tqdm(concurrent.futures.as_completed(future_to_nsg), total=len(nsgs), desc="Processing NSGs"):
                nsg = future_to_nsg[future]
                try:
                    records = future.result()
                    if not records:
                        continue
                    
                    # Filter records if needed
                    filtered_records = filter_records(records, args.ip, args.subnet)
                    if filtered_records:
                        all_records.extend(filtered_records)
                        if args.verbose:
                            print(f"Found {len(filtered_records)} matching records in NSG: {nsg['name']}")
                except Exception as e:
                    print(f"Error processing NSG {nsg['name']}: {str(e)}")
        
        if not all_records:
            print("No matching flow log records found. Exiting.")
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
