#!/usr/bin/env python3
"""
ip_nsg_finder.py - Find NSGs associated with an IP address

Usage: python ip_nsg_finder.py <IP_address> [--analyze] [--time-range HOURS]

This script finds NSGs associated with a specified IP address,
allowing for subsequent traffic log queries using Azure Log Analytics.
"""

import os
import sys
import json
import argparse
import subprocess
import ipaddress
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional, Tuple

# Terminal output colors
class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    RESET = '\033[0m'
    BOLD = '\033[1m'

def print_info(text: str) -> None:
    """Print informational message"""
    print(f"{Colors.BLUE}{text}{Colors.RESET}")

def print_success(text: str) -> None:
    """Print success message"""
    print(f"{Colors.GREEN}{text}{Colors.RESET}")

def print_warning(text: str) -> None:
    """Print warning message"""
    print(f"{Colors.YELLOW}{text}{Colors.RESET}")

def print_error(text: str) -> None:
    """Print error message"""
    print(f"{Colors.RED}{text}{Colors.RESET}")

def save_json(data: Any, file_path: str) -> None:
    """Save data to JSON file"""
    with open(file_path, 'w') as f:
        json.dump(data, f, indent=2)
    print_info(f"Saved data to {file_path}")

def run_command(cmd: str) -> Optional[Dict]:
    """Run command and return JSON result"""
    try:
        print_info(f"Executing command: {cmd}")
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, check=False)
        
        if result.returncode != 0:
            print_error(f"Command execution failed: {result.stderr}")
            return None
            
        if not result.stdout.strip():
            print_warning("Command executed successfully but returned no output")
            return None
            
        try:
            return json.loads(result.stdout)
        except json.JSONDecodeError:
            # Response might not be in JSON format
            print_info(f"Command output: {result.stdout}")
            return {"raw_output": result.stdout.strip()}
    except Exception as e:
        print_error(f"Error running command: {str(e)}")
        return None

def ip_in_subnet(ip_address: str, subnet_prefix: str) -> bool:
    """Check if IP is within subnet range using ipaddress module"""
    try:
        network = ipaddress.ip_network(subnet_prefix, strict=False)
        ip = ipaddress.ip_address(ip_address)
        return ip in network
    except ValueError as e:
        print_warning(f"Error parsing IP or subnet prefix: {str(e)}")
        return False

def find_nsgs_by_ip(target_ip: str) -> List[str]:
    """Find list of NSG IDs associated with an IP"""
    print_info(f"\nFinding NSGs associated with IP {target_ip}...")
    nsg_ids = []
    output_dir = "output"
    os.makedirs(output_dir, exist_ok=True)
    
    # 1. Find network interfaces directly using this IP
    print_info("\nStep 1: Finding network interfaces directly using this IP...")
    nic_cmd = f"az graph query -q \"Resources | where type =~ 'microsoft.network/networkinterfaces' | where properties.ipConfigurations[0].properties.privateIPAddress =~ '{target_ip}' | project id, name, resourceGroup, vnetId = tostring(properties.ipConfigurations[0].properties.subnet.id), nsgId = tostring(properties.networkSecurityGroup.id)\" --query \"data\" -o json"
    
    nics = run_command(nic_cmd)
    if nics:
        save_json(nics, os.path.join(output_dir, "network_interfaces.json"))
        print_success(f"Found {len(nics)} network interfaces using IP {target_ip}")
        
        # 1.1 Collect NSGs directly associated with NICs
        for nic in nics:
            nsg_id = nic.get('nsgId')
            if nsg_id and nsg_id not in nsg_ids:
                nsg_ids.append(nsg_id)
                print_success(f"Found NSG from network interface: {nsg_id}")
        
        # 1.2 Get subnet IDs from network interfaces
        subnet_ids = []
        for nic in nics:
            subnet_id = nic.get('vnetId')
            if subnet_id and subnet_id not in subnet_ids:
                subnet_ids.append(subnet_id)
                print_success(f"Found subnet ID: {subnet_id}")
                
                # Extract VNET name and subnet name from subnet ID
                parts = subnet_id.split('/')
                resource_group = None
                vnet_name = None 
                subnet_name = None
                
                for i, part in enumerate(parts):
                    if part.lower() == 'resourcegroups' and i+1 < len(parts):
                        resource_group = parts[i+1]
                    elif part.lower() == 'virtualnetworks' and i+1 < len(parts):
                        vnet_name = parts[i+1]
                    elif part.lower() == 'subnets' and i+1 < len(parts):
                        subnet_name = parts[i+1]
                
                if resource_group and vnet_name and subnet_name:
                    print_info(f"Subnet info parsed: Resource Group={resource_group}, VNET={vnet_name}, Subnet={subnet_name}")
                    
                    # 2. Get detailed subnet information directly from Azure
                    print_info(f"\nStep 2: Getting detailed subnet information for {subnet_name}...")
                    subnet_cmd = f"az network vnet subnet show --resource-group {resource_group} --vnet-name {vnet_name} --name {subnet_name} -o json"
                    subnet_details = run_command(subnet_cmd)
                    
                    if subnet_details:
                        save_json(subnet_details, os.path.join(output_dir, f"subnet_{subnet_name}.json"))
                        
                        # Extract NSG associated with the subnet
                        subnet_nsg = subnet_details.get('networkSecurityGroup', {})
                        if isinstance(subnet_nsg, dict) and 'id' in subnet_nsg:
                            subnet_nsg_id = subnet_nsg['id']
                            if subnet_nsg_id and subnet_nsg_id not in nsg_ids:
                                nsg_ids.append(subnet_nsg_id)
                                print_success(f"Found NSG from subnet {subnet_name}: {subnet_nsg_id}")
    else:
        print_warning(f"No network interfaces found using IP {target_ip}")
        
        # 3. If no network interfaces found, try to find subnets containing this IP
        print_info("\nStep 3: Looking for subnets containing this IP...")
        
        # 3.1 Query all subnets
        subnets_cmd = "az graph query -q \"Resources | where type =~ 'microsoft.network/virtualnetworks' | mv-expand subnet=properties.subnets | project vnetName=name, vnetId=id, resourceGroup=resourceGroup, subnetName=subnet.name, subnetPrefix=subnet.properties.addressPrefix, subnetId=subnet.id, nsgId=tostring(subnet.properties.networkSecurityGroup.id)\" --query \"data\" -o json"
        
        all_subnets = run_command(subnets_cmd)
        if all_subnets:
            save_json(all_subnets, os.path.join(output_dir, "all_subnets.json"))
            print_success(f"Found {len(all_subnets)} subnets")
            
            # Check each subnet to see if it contains this IP
            for subnet in all_subnets:
                subnet_prefix = subnet.get('subnetPrefix')
                
                # Subnet prefix could be string or list
                prefixes = []
                if isinstance(subnet_prefix, list):
                    prefixes.extend(subnet_prefix)
                elif subnet_prefix:
                    prefixes.append(subnet_prefix)
                
                for prefix in prefixes:
                    if prefix and ip_in_subnet(target_ip, prefix):
                        print_success(f"IP {target_ip} is within subnet {subnet.get('subnetName')} range {prefix}")
                        
                        # Get NSG associated with the subnet
                        nsg_id = subnet.get('nsgId')
                        if nsg_id and nsg_id not in nsg_ids:
                            nsg_ids.append(nsg_id)
                            print_success(f"Found NSG from subnet {subnet.get('subnetName')}: {nsg_id}")
                        else:
                            print_warning(f"Subnet {subnet.get('subnetName')} has no associated NSG or NSG already recorded")
                        
                        # Get more subnet details
                        resource_group = subnet.get('resourceGroup')
                        vnet_name = subnet.get('vnetName')
                        subnet_name = subnet.get('subnetName')
                        
                        if resource_group and vnet_name and subnet_name:
                            subnet_cmd = f"az network vnet subnet show --resource-group {resource_group} --vnet-name {vnet_name} --name {subnet_name} -o json"
                            subnet_details = run_command(subnet_cmd)
                            
                            if subnet_details:
                                save_json(subnet_details, os.path.join(output_dir, f"subnet_{subnet_name}.json"))
        else:
            print_warning("Unable to get subnet list")
    
    # Save all NSG IDs found
    if nsg_ids:
        save_json(nsg_ids, os.path.join(output_dir, "nsg_ids.json"))
        print_success(f"\nTotal NSGs found for IP {target_ip}: {len(nsg_ids)}")
        for i, nsg_id in enumerate(nsg_ids):
            print(f"  {i+1}. {nsg_id}")
    else:
        print_warning(f"\nNo NSGs found for IP {target_ip}")
    
    return nsg_ids

def get_nsg_flow_logs_config(nsg_ids: List[str]) -> Dict[str, Dict]:
    """Get flow logs configuration for NSGs"""
    print_info("\nStep 4: Getting NSG flow logs configuration...")
    output_dir = "output"
    os.makedirs(output_dir, exist_ok=True)
    
    flow_logs_config = {}
    
    for nsg_id in nsg_ids:
        # Extract resource group and NSG name from NSG ID
        parts = nsg_id.split('/')
        resource_group = None
        nsg_name = None
        
        for i, part in enumerate(parts):
            if part.lower() == 'resourcegroups' and i+1 < len(parts):
                resource_group = parts[i+1]
            elif part.lower() == 'networksecuritygroups' and i+1 < len(parts):
                nsg_name = parts[i+1]
        
        if not resource_group or not nsg_name:
            print_warning(f"Unable to extract resource group and NSG name from NSG ID: {nsg_id}")
            continue
            
        print_info(f"Getting flow logs configuration for NSG {nsg_name}...")
        
        # Query flow logs configuration via Azure CLI
        flow_logs_cmd = f"az network watcher flow-log list --resource-group {resource_group} --query \"[?contains(targetResourceId, '{nsg_id}')]\" -o json"
        flow_logs = run_command(flow_logs_cmd)
        
        if not flow_logs:
            # Alternative method using Resource Graph
            print_info(f"Trying Resource Graph to query flow logs for NSG {nsg_name}...")
            flow_logs_cmd = f"az graph query -q \"Resources | where type =~ 'Microsoft.Network/networkWatchers/flowLogs' | where properties.targetResourceId =~ '{nsg_id}' | project id, name, resourceGroup, flowLogResourceId=id, workspaceId=properties.flowAnalyticsConfiguration.networkWatcherFlowAnalyticsConfiguration.workspaceId, workspaceRegion=properties.flowAnalyticsConfiguration.networkWatcherFlowAnalyticsConfiguration.workspaceRegion, enabled=properties.enabled, retentionPolicy=properties.retentionPolicy\" --query \"data\" -o json"
            flow_logs = run_command(flow_logs_cmd)
        
        if flow_logs:
            if isinstance(flow_logs, list):
                if len(flow_logs) > 0:
                    print_success(f"Found flow logs configuration for NSG {nsg_name}")
                    flow_logs_config[nsg_id] = flow_logs[0]
                    save_json(flow_logs, os.path.join(output_dir, f"flow_logs_{nsg_name}.json"))
                else:
                    print_warning(f"NSG {nsg_name} has no flow logs configured")
            else:
                print_success(f"Found flow logs configuration for NSG {nsg_name}")
                flow_logs_config[nsg_id] = flow_logs
                save_json(flow_logs, os.path.join(output_dir, f"flow_logs_{nsg_name}.json"))
        else:
            print_warning(f"Unable to get flow logs configuration for NSG {nsg_name}")
    
    # Save all flow logs configurations
    if flow_logs_config:
        save_json(flow_logs_config, os.path.join(output_dir, "flow_logs_config.json"))
        print_success(f"Saved flow logs configuration for {len(flow_logs_config)} NSGs")
    else:
        print_warning("No NSG flow logs configuration found")
    
    return flow_logs_config

def get_log_analytics_workspaces(flow_logs_config: Dict[str, Dict]) -> Dict[str, str]:
    """Extract Log Analytics workspace IDs from flow logs configuration"""
    print_info("\nStep 5: Extracting Log Analytics workspace information...")
    workspace_ids = {}
    
    for nsg_id, config in flow_logs_config.items():
        workspace_id = None
        
        # Try different paths to find workspace ID
        if isinstance(config, dict):
            if 'workspaceId' in config:
                workspace_id = config['workspaceId']
            elif 'flowAnalyticsConfiguration' in config.get('properties', {}):
                analytics_config = config['properties']['flowAnalyticsConfiguration']
                if isinstance(analytics_config, dict) and 'networkWatcherFlowAnalyticsConfiguration' in analytics_config:
                    flow_analytics = analytics_config['networkWatcherFlowAnalyticsConfiguration']
                    if isinstance(flow_analytics, dict) and 'workspaceId' in flow_analytics:
                        workspace_id = flow_analytics['workspaceId']
            elif 'properties' in config and 'flowAnalytics' in config['properties']:
                flow_analytics = config['properties']['flowAnalytics']
                if isinstance(flow_analytics, dict) and 'workspaceId' in flow_analytics:
                    workspace_id = flow_analytics['workspaceId']
        
        if workspace_id:
            nsg_name = nsg_id.split('/')[-1]
            workspace_ids[nsg_id] = workspace_id
            print_success(f"Log Analytics workspace ID for NSG {nsg_name}: {workspace_id}")
    
    # Save workspace IDs
    if workspace_ids:
        output_dir = "output"
        save_json(workspace_ids, os.path.join(output_dir, "workspace_ids.json"))
        print_success(f"Found {len(workspace_ids)} Log Analytics workspace IDs")
    else:
        print_warning("No Log Analytics workspace IDs found")
    
    return workspace_ids

def execute_kql_query(workspace_id: str, kql_query: str, timeout_seconds: int = 60) -> Optional[Dict]:
    """Execute a KQL query against a Log Analytics workspace"""
    print_info(f"\nExecuting KQL query against workspace: {workspace_id}")
    
    # Construct Azure CLI command to run the query
    # Add timeout to prevent hanging indefinitely
    cmd = f"az monitor log-analytics query --workspace {workspace_id} --analytics-query \"{kql_query}\" --timespan {timeout_seconds}m -o json"
    
    # Execute the query
    results = run_command(cmd)
    
    if results:
        # Save results
        output_dir = "output"
        os.makedirs(output_dir, exist_ok=True)
        
        workspace_short_id = workspace_id.split('/')[-1]
        result_path = os.path.join(output_dir, f"query_results_{workspace_short_id}.json")
        
        save_json(results, result_path)
        print_success(f"Query results saved to {result_path}")
        
        # Print summary
        if isinstance(results, list):
            print_success(f"Query returned {len(results)} records")
            if len(results) > 0:
                print_info("Sample records:")
                for i, record in enumerate(results[:3]):  # Show up to 3 records
                    print(json.dumps(record, indent=2))
                    if i < len(results[:3]) - 1:
                        print("---")
        else:
            print_success("Query executed but returned data structure is not the expected list format")
    else:
        print_warning("Failed to execute KQL query or no results returned")
    
    return results

def generate_simple_kql_query(target_ip: str, time_range_hours: int = 24) -> str:
    """Generate a simple KQL query without NSG filtering"""
    
    # Get current time and time range
    end_time = datetime.utcnow()
    start_time = end_time - timedelta(hours=time_range_hours)
    
    # Format times for KQL query
    start_time_str = start_time.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    end_time_str = end_time.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    
    # Basic KQL query for NSG flow logs without NSG filtering
    query = f"""
AzureNetworkAnalytics_CL
| where TimeGenerated between (datetime({start_time_str}) .. datetime({end_time_str}))
| where FlowType_s == "Flow"
| where SrcIP_s == "{target_ip}" or DestIP_s == "{target_ip}"
| project TimeGenerated, 
          NSGName_s, 
          FlowDirection_s, 
          SrcIP_s, 
          DestIP_s, 
          SrcPort_d, 
          DestPort_d, 
          Protocol_s, 
          FlowStatus_s,
          L7Protocol_s,
          AllowedInFlows_d,
          AllowedOutFlows_d,
          DeniedInFlows_d,
          DeniedOutFlows_d
| sort by TimeGenerated desc
| limit 1000
"""
    return query

def generate_kql_query(target_ip: str, 
                      flow_logs_config: Dict[str, Dict], 
                      workspace_ids: Dict[str, str],
                      time_range_hours: int = 24,
                      filter_by_nsg: bool = True) -> Dict[str, str]:
    """Generate KQL queries for each workspace"""
    print_info("\nStep 6: Generating KQL queries...")
    output_dir = "output"
    os.makedirs(output_dir, exist_ok=True)
    
    kql_queries = {}
    
    # Get current time and time range
    end_time = datetime.utcnow()
    start_time = end_time - timedelta(hours=time_range_hours)
    
    # Format times for KQL query
    start_time_str = start_time.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    end_time_str = end_time.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    
    # Create a mapping of workspace ID to NSG IDs
    workspace_to_nsgs = {}
    for nsg_id, workspace_id in workspace_ids.items():
        if workspace_id not in workspace_to_nsgs:
            workspace_to_nsgs[workspace_id] = []
        workspace_to_nsgs[workspace_id].append(nsg_id)
    
    # Generate KQL query for each workspace
    for workspace_id, nsg_ids in workspace_to_nsgs.items():
        # Create NSG filter condition if needed
        nsg_filter = ""
        if filter_by_nsg:
            nsg_names = []
            for nsg_id in nsg_ids:
                nsg_name = nsg_id.split('/')[-1]
                nsg_names.append(nsg_name)
            
            # Only add NSG filter if we have NSGs to filter
            if nsg_names:
                nsg_filter = f"| where ({' or '.join([f'NSGName_s == \"{name}\"' for name in nsg_names])})\n"
        
        # Basic KQL query for NSG flow logs
        query = f"""
AzureNetworkAnalytics_CL
| where TimeGenerated between (datetime({start_time_str}) .. datetime({end_time_str}))
| where FlowType_s == "Flow" 
{nsg_filter}| where SrcIP_s == "{target_ip}" or DestIP_s == "{target_ip}"
| project TimeGenerated, 
          NSGName_s, 
          FlowDirection_s, 
          SrcIP_s, 
          DestIP_s, 
          SrcPort_d, 
          DestPort_d, 
          Protocol_s, 
          FlowStatus_s,
          L7Protocol_s,
          AllowedInFlows_d,
          AllowedOutFlows_d,
          DeniedInFlows_d,
          DeniedOutFlows_d
| sort by TimeGenerated desc
| limit 1000
"""
        
        # Create a short name for the workspace for filename
        workspace_short_id = workspace_id.split('/')[-1]
        
        # Save the query to a file
        query_filename = f"kql_query_{workspace_short_id}.kql"
        query_path = os.path.join(output_dir, query_filename)
        
        with open(query_path, 'w') as f:
            f.write(query)
        
        print_success(f"Generated KQL query and saved to {query_path}")
        
        # Add query to return dictionary
        kql_queries[workspace_id] = query
    
    # Save all queries
    if kql_queries:
        save_json({k: v for k, v in kql_queries.items()}, os.path.join(output_dir, "kql_queries.json"))
        print_success(f"Generated a total of {len(kql_queries)} KQL queries")
    else:
        print_warning("Could not generate any KQL queries")
    
    return kql_queries

def analyze_traffic(target_ip: str, time_range_hours: int = 24, filter_by_nsg: bool = True, execute_query: bool = False, timeout_seconds: int = 60) -> Dict[str, Any]:
    """Main function to analyze traffic for an IP address"""
    output_dir = "output"
    os.makedirs(output_dir, exist_ok=True)
    
    results = {
        "target_ip": target_ip,
        "time_range_hours": time_range_hours,
        "timestamp": datetime.utcnow().isoformat(),
        "nsg_ids": [],
        "workspaces": {},
        "kql_results": {}
    }
    
    # Step 1: Find NSGs associated with the IP
    print_info("\n====== Phase 1: Finding related NSGs ======")
    nsg_ids = find_nsgs_by_ip(target_ip)
    results["nsg_ids"] = nsg_ids
    
    if not nsg_ids:
        print_warning("No NSGs found for the IP, but we can still try direct KQL query")
        
        # Ask user if they want to proceed with direct query
        if execute_query or input("\nDo you want to proceed with direct KQL query without NSG information? (y/n): ").lower().strip() == 'y':
            workspace_id = input("\nPlease enter the Log Analytics workspace ID: ").strip()
            if workspace_id:
                query = generate_simple_kql_query(target_ip, time_range_hours)
                result_path = os.path.join(output_dir, f"simple_kql_query.kql")
                with open(result_path, 'w') as f:
                    f.write(query)
                print_success(f"Generated simple KQL query and saved to {result_path}")
                
                if execute_query or input("\nDo you want to execute this query now? (y/n): ").lower().strip() == 'y':
                    query_results = execute_kql_query(workspace_id, query, timeout_seconds)
                    results["kql_results"][workspace_id] = query_results
            else:
                print_warning("No workspace ID provided, cannot proceed with query")
        
        save_json(results, os.path.join(output_dir, "analysis_results.json"))
        return results
    
    # Step 2: Get NSG flow logs configuration
    print_info("\n====== Phase 2: Getting flow logs configuration ======")
    flow_logs_config = get_nsg_flow_logs_config(nsg_ids)
    results["flow_logs_config"] = flow_logs_config
    
    if not flow_logs_config:
        print_warning("No NSG flow logs configuration found, trying direct query")
        
        if execute_query or input("\nDo you want to proceed with direct KQL query without flow logs configuration? (y/n): ").lower().strip() == 'y':
            workspace_id = input("\nPlease enter the Log Analytics workspace ID: ").strip()
            if workspace_id:
                query = generate_simple_kql_query(target_ip, time_range_hours)
                result_path = os.path.join(output_dir, f"simple_kql_query.kql")
                with open(result_path, 'w') as f:
                    f.write(query)
                print_success(f"Generated simple KQL query and saved to {result_path}")
                
                if execute_query or input("\nDo you want to execute this query now? (y/n): ").lower().strip() == 'y':
                    query_results = execute_kql_query(workspace_id, query, timeout_seconds)
                    results["kql_results"][workspace_id] = query_results
            else:
                print_warning("No workspace ID provided, cannot proceed with query")
                
        save_json(results, os.path.join(output_dir, "analysis_results.json"))
        return results
    
    # Step 3: Extract Log Analytics workspace IDs
    print_info("\n====== Phase 3: Extracting workspace information ======")
    workspace_ids = get_log_analytics_workspaces(flow_logs_config)
    results["workspaces"] = workspace_ids
    
    if not workspace_ids:
        print_warning("No Log Analytics workspace IDs found, asking for manual input")
        
        if execute_query or input("\nDo you want to proceed with direct KQL query by entering workspace ID manually? (y/n): ").lower().strip() == 'y':
            workspace_id = input("\nPlease enter the Log Analytics workspace ID: ").strip()
            if workspace_id:
                # Add the workspace ID to results
                results["workspaces"]["manual"] = workspace_id
                
                # Create a simple query based on IP only
                query = generate_simple_kql_query(target_ip, time_range_hours)
                result_path = os.path.join(output_dir, f"simple_kql_query.kql")
                with open(result_path, 'w') as f:
                    f.write(query)
                print_success(f"Generated simple KQL query and saved to {result_path}")
                
                if execute_query or input("\nDo you want to execute this query now? (y/n): ").lower().strip() == 'y':
                    query_results = execute_kql_query(workspace_id, query, timeout_seconds)
                    results["kql_results"][workspace_id] = query_results
            else:
                print_warning("No workspace ID provided, cannot proceed with query")
                
        save_json(results, os.path.join(output_dir, "analysis_results.json"))
        return results
    
    # Step 4: Generate KQL queries
    print_info("\n====== Phase 4: Generating KQL queries ======")
    kql_queries = generate_kql_query(target_ip, flow_logs_config, workspace_ids, time_range_hours, filter_by_nsg)
    results["kql_queries"] = kql_queries
    
    if not kql_queries:
        print_warning("Could not generate KQL queries, cannot continue")
        save_json(results, os.path.join(output_dir, "analysis_results.json"))
        return results
    
    # Step 5: Execute KQL queries (optional)
    should_execute = execute_query or input("\nDo you want to execute the KQL queries? (y/n): ").lower().strip() == 'y'
    if should_execute:
        print_info("\n====== Phase 5: Executing KQL queries ======")
        for workspace_id, query in kql_queries.items():
            query_results = execute_kql_query(workspace_id, query, timeout_seconds)
            results["kql_results"][workspace_id] = query_results
    
    # Save final results
    save_json(results, os.path.join(output_dir, "analysis_results.json"))
    
    return results

def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(description='Find NSGs associated with an IP address and analyze traffic')
    parser.add_argument('ip_address', help='The IP address to query')
    parser.add_argument('--time-range', type=int, default=24, help='Time range in hours for traffic analysis (default: 24)')
    parser.add_argument('--analyze', action='store_true', help='Perform full traffic analysis including KQL query generation')
    parser.add_argument('--execute', action='store_true', help='Execute KQL queries automatically (implies --analyze)')
    parser.add_argument('--timeout', type=int, default=60, help='Timeout in seconds for KQL query execution (default: 60)')
    parser.add_argument('--no-nsg-filter', action='store_true', help='Do not filter KQL queries by NSG names')
    parser.add_argument('--direct-query', action='store_true', help='Skip NSG discovery and directly query by IP')
    parser.add_argument('--workspace-id', help='Directly specify Log Analytics workspace ID')
    
    args = parser.parse_args()
    
    # Validate IP address format
    try:
        ipaddress.ip_address(args.ip_address)
    except ValueError:
        print_error(f"Invalid IP address format: {args.ip_address}")
        sys.exit(1)
    
    print_info("=" * 60)
    print_success(f"IP NSG Analyzer")
    print_info("=" * 60)
    print(f"Target IP: {args.ip_address}")
    print(f"Time range: {args.time_range} hours")
    
    # Display analysis mode
    if args.direct_query:
        print("Analysis mode: Direct KQL query")
    elif args.analyze or args.execute:
        print(f"Analysis mode: {'Full with query execution' if args.execute else 'Full'}")
    else:
        print("Analysis mode: Basic (NSG discovery only)")
    
    # Display filter settings
    if args.no_nsg_filter:
        print("NSG filtering: Disabled")
    
    print_info("=" * 60)
    
    # Direct query mode
    if args.direct_query:
        if not args.workspace_id:
            args.workspace_id = input("\nPlease enter the Log Analytics workspace ID: ").strip()
            if not args.workspace_id:
                print_error("Workspace ID is required for direct query mode")
                sys.exit(1)
        
        output_dir = "output"
        os.makedirs(output_dir, exist_ok=True)
        
        # Generate a simple query
        query = generate_simple_kql_query(args.ip_address, args.time_range)
        result_path = os.path.join(output_dir, f"direct_kql_query.kql")
        with open(result_path, 'w') as f:
            f.write(query)
        print_success(f"Generated direct KQL query and saved to {result_path}")
        
        # Execute if requested
        if args.execute:
            print_info("\n====== Executing Direct KQL Query ======")
            results = execute_kql_query(args.workspace_id, query, args.timeout)
            save_json(results or {}, os.path.join(output_dir, "direct_query_results.json"))
    elif args.execute:
        # Full analysis with query execution
        analyze_traffic(args.ip_address, args.time_range, not args.no_nsg_filter, True, args.timeout)
    elif args.analyze:
        # Perform full analysis
        analyze_traffic(args.ip_address, args.time_range, not args.no_nsg_filter)
    elif args.workspace_id:
        # If workspace ID is provided, perform simple query
        output_dir = "output"
        os.makedirs(output_dir, exist_ok=True)
        
        query = generate_simple_kql_query(args.ip_address, args.time_range)
        result_path = os.path.join(output_dir, f"workspace_query.kql")
        with open(result_path, 'w') as f:
            f.write(query)
        print_success(f"Generated KQL query for specified workspace and saved to {result_path}")
        
        if input("\nDo you want to execute this query now? (y/n): ").lower().strip() == 'y':
            results = execute_kql_query(args.workspace_id, query, args.timeout)
            save_json(results or {}, os.path.join(output_dir, "workspace_query_results.json"))
    else:
        # Just find NSGs
        nsg_ids = find_nsgs_by_ip(args.ip_address)
        
        # Validate NSGs found
        if nsg_ids:
            print_success("\nSearch completed! NSGs found.")
            print_info("To perform full traffic analysis, run the script with the --analyze parameter")
        else:
            print_warning("\nSearch completed, but no NSGs found.")
            if input("Do you want to proceed with direct KQL query? (y/n): ").lower().strip() == 'y':
                workspace_id = input("\nPlease enter the Log Analytics workspace ID: ").strip()
                if workspace_id:
                    output_dir = "output"
                    os.makedirs(output_dir, exist_ok=True)
                    
                    query = generate_simple_kql_query(args.ip_address, args.time_range)
                    result_path = os.path.join(output_dir, f"direct_kql_query.kql")
                    with open(result_path, 'w') as f:
                        f.write(query)
                    print_success(f"Generated KQL query and saved to {result_path}")
                    
                    if input("\nDo you want to execute this query now? (y/n): ").lower().strip() == 'y':
                        results = execute_kql_query(workspace_id, query, args.timeout)
                        save_json(results or {}, os.path.join(output_dir, "direct_query_results.json"))
    
if __name__ == "__main__":
    main()
