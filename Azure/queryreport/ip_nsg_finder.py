import os
import sys
import json
import argparse
import subprocess
import ipaddress
import re
from datetime import datetime, timedelta, timezone
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
    with open(file_path, 'w', encoding='utf-8') as f:
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
        
        # First try using Resource Graph to directly query for flow logs - more reliable method
        flow_logs_cmd = f"az graph query -q \"Resources | where type =~ 'Microsoft.Network/networkWatchers/flowLogs' | where properties.targetResourceId =~ '{nsg_id}' | project id, name, resourceGroup, flowLogResourceId=id, workspaceId=properties.flowAnalyticsConfiguration.networkWatcherFlowAnalyticsConfiguration.workspaceId, workspaceRegion=properties.flowAnalyticsConfiguration.networkWatcherFlowAnalyticsConfiguration.workspaceRegion, enabled=properties.enabled, retentionPolicy=properties.retentionPolicy\" --query \"data\" -o json"
        
        print_info(f"Executing command: {flow_logs_cmd}")
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
            # As fallback, try a more direct method to find the workspace ID
            # This is just a workaround since we don't need the full config
            print_warning(f"Could not get flow logs config. Using alternative method to find workspace...")
            
            # Try to find the appropriate workspace ID based on NSG location
            workspace_cmd = f"az graph query -q \"Resources | where type =~ 'Microsoft.OperationalInsights/workspaces' | project id, name, location, resourceGroup\" --query \"data\" -o json"
            workspaces = run_command(workspace_cmd)
            
            if workspaces and isinstance(workspaces, list) and len(workspaces) > 0:
                # For simplicity, just use the first workspace found
                # In production, you would need to match by location/subscription
                workspace = workspaces[0]
                workspace_id = workspace.get('id')
                
                if workspace_id:
                    print_success(f"Using workspace {workspace.get('name')} as fallback")
                    # Create minimal flow log config with just the workspace ID
                    flow_logs_config[nsg_id] = {
                        "workspaceId": workspace_id,
                        "name": f"fallback-for-{nsg_name}"
                    }
    
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
 
     # Format the query to ensure it's properly escaped
     # Remove any leading/trailing whitespace and newlines
     kql_query = kql_query.strip()
 
     # Make sure workspace ID is properly formatted
     if '/' in workspace_id:  # If it's a full resource ID
         # Extract just the workspace ID part at the end
         workspace_id = workspace_id.split('/')[-1]
 
     # Handle timespan parameter - use PT format for Azure CLI
     # PT<minutes>M format required by Azure CLI, adjust based on timeout_seconds
     # Ensure minimum 1 minute timespan for the parameter format
     timespan_minutes = max(1, timeout_seconds // 60)
     timespan_param = f"PT{timespan_minutes}M"
 
     # Create a temporary file with the query to avoid command line length issues
     temp_query_file = os.path.join("output", f"temp_query_{workspace_id}.kql")
     os.makedirs("output", exist_ok=True)
     try:
         with open(temp_query_file, 'w', encoding='utf-8') as f:
             f.write(kql_query)
     except IOError as e:
         print_error(f"Failed to write temporary query file {temp_query_file}: {e}")
         return None
 
     # Log query details to log file for troubleshooting
     log_file = os.path.join("output", "kql_commands.log")
     try:
         with open(log_file, 'a') as f:
             f.write(f"\n\n--- QUERY EXECUTION: {datetime.now(timezone.utc)} ---\n")
             f.write(f"Workspace ID: {workspace_id}\n")
             f.write(f"Timeout Seconds: {timeout_seconds}\n")
             f.write(f"Query File: {temp_query_file}\n")
             f.write(f"Query Content:\n{kql_query}\n")
     except IOError as e:
         print_warning(f"Could not write to log file {log_file}: {e}")
 
 
     # Construct Azure CLI command with proper parameters
     # Using @file syntax is generally robust against shell quoting issues
     cmd = f"az monitor log-analytics query --workspace {workspace_id} --analytics-query \"@{temp_query_file}\" -o json"
 
     print_info(f"Query command: az monitor log-analytics query --workspace {workspace_id} --analytics-query \"@{temp_query_file}\" -o json ...") # Avoid printing full command if too long
     # Log complete command to log file
     try:
         with open(log_file, 'a') as f:
             f.write(f"Command: {cmd}\n")
     except IOError as e:
         print_warning(f"Could not write command to log file {log_file}: {e}")
 
     # Execute the query with extended timeout
     stdout, stderr = "", ""
     process = None
     try:
         process = subprocess.Popen(
             cmd,
             shell=True, # shell=True is often needed for complex az cli commands, especially with @file
             stdout=subprocess.PIPE,
             stderr=subprocess.PIPE,
             text=True,
             encoding='utf-8' # Specify encoding
         )
 
         # Wait with timeout (allow ample time, e.g., 3x query timeout + buffer)
         stdout, stderr = process.communicate(timeout=timeout_seconds * 3 + 30) # Added buffer
 
         # Log output results to log file
         try:
             with open(log_file, 'a') as f:
                 f.write(f"ReturnCode: {process.returncode}\n")
                 f.write(f"StdErr: {stderr}\n")
                 # Avoid logging excessively large stdout
                 stdout_preview = stdout[:2000] + ('...' if len(stdout) > 2000 else '')
                 f.write(f"StdOut Preview: {stdout_preview}\n")
         except IOError as e:
             print_warning(f"Could not write results to log file {log_file}: {e}")
 
 
         if process.returncode != 0:
             # Check for specific common errors first
             if "ResponseSizeError" in stderr or "Response size too large" in stderr:
                 print_error("Query result exceeded maximum size limit. Consider reducing the time range or adding more filters.")
                 # Log this specific error
                 try:
                     with open(log_file, 'a') as f: f.write("Error Type: ResponseSizeError\n")
                 except IOError: pass
                 # Note: Retrying with smaller limit is complex and might hide the real issue.
                 # Better to inform the user to refine the query/time range.
                 return None # Stop execution for this query
 
             elif "SemanticError" in stderr:
                 error_detail = stderr # Capture the full error
                 print_error(f"KQL Semantic Error: Table or field name likely incorrect for workspace '{workspace_id}'.")
                 print_error("Please check the KQL query and verify table/field names (e.g., AzureNetworkAnalytics_CL, NetworkMonitoring, SrcIP_s) exist in this workspace.")
                 print_error(f"See details in log file: {log_file}")
                 # Log the detailed error
                 try:
                     with open(log_file, 'a') as f:
                         f.write(f"Error Type: SemanticError\n")
                         f.write(f"SemanticError Detail: {error_detail}\n")
                 except IOError: pass
                 # Attempting to find tables might fail if the initial query already failed semantically.
                 # Focus on informing the user.
                 return None # Stop execution for this query
 
             elif "AuthenticationFailed" in stderr or "AuthorizationFailed" in stderr:
                  print_error(f"Authentication/Authorization Failed for workspace '{workspace_id}'. Check Azure login and permissions.")
                  print_error(f"See details in log file: {log_file}")
                  try:
                      with open(log_file, 'a') as f: f.write("Error Type: Authentication/Authorization Failed\n")
                  except IOError: pass
                  return None
 
             else:
                 # Generic error
                 print_error(f"Query execution failed with return code {process.returncode}.")
                 print_error(f"Stderr: {stderr}")
                 print_error(f"See details in log file: {log_file}")
                 return None
 
         # Check if stdout is empty even on success
         if not stdout or not stdout.strip():
             print_warning("Query executed successfully but returned no data.")
             return {"tables": []} # Return structure expected by downstream processing
 
         # Try parsing the JSON result
         try:
             results = json.loads(stdout)
             # Basic validation of expected structure (adjust if needed)
             if not isinstance(results, dict) or 'tables' not in results:
                  print_warning(f"Query returned unexpected JSON structure. Raw output saved.")
                  # Save raw output for debugging
                  raw_output_path = os.path.join("output", f"query_results_{workspace_id}_raw.txt")
                  try:
                      with open(raw_output_path, 'w', encoding='utf-8') as rf: rf.write(stdout)
                      print_info(f"Raw output saved to {raw_output_path}")
                  except IOError as e:
                      print_warning(f"Could not save raw output: {e}")
                  return {"tables": []} # Return empty structure
 
             # Save results
             output_dir = "output"
             # No need for os.makedirs here, already done above
 
             workspace_short_id = workspace_id.split('/')[-1] if '/' in workspace_id else workspace_id
             result_path = os.path.join(output_dir, f"query_results_{workspace_short_id}.json")
 
             save_json(results, result_path) # Use the existing save_json function
             # print_success(f"Query results saved to {result_path}") # save_json already prints
 
             # Print summary
             result_count = 0
             if isinstance(results.get('tables'), list) and len(results['tables']) > 0 and isinstance(results['tables'][0].get('rows'), list):
                 result_count = len(results['tables'][0]['rows'])
 
             print_success(f"Query returned {result_count} records.")
 
             # Print sample records (if any)
             if result_count > 0:
                 print_info("Sample records (up to 3):")
                 sample_size = min(3, result_count)
                 columns = [col['name'] for col in results['tables'][0]['columns']]
                 for i in range(sample_size):
                     row_data = dict(zip(columns, results['tables'][0]['rows'][i]))
                     print(json.dumps(row_data, indent=2))
                     if i < sample_size - 1:
                         print("---")
 
             return results # Return the parsed results
 
         except json.JSONDecodeError as e:
             print_error(f"Failed to parse query results as JSON: {e}")
             print_info(f"Raw output preview: {stdout[:500]}...")
             # Save raw output for debugging
             raw_output_path = os.path.join("output", f"query_results_{workspace_id}_raw.txt")
             try:
                 with open(raw_output_path, 'w', encoding='utf-8') as rf: rf.write(stdout)
                 print_info(f"Raw output saved to {raw_output_path}")
             except IOError as ioe:
                 print_warning(f"Could not save raw output: {ioe}")
             return None # Indicate failure
 
     except subprocess.TimeoutExpired:
         print_error(f"Query execution timed out after {timeout_seconds*3 + 30} seconds for workspace {workspace_id}.")
         if process: process.kill() # Ensure the process is terminated
         try:
             with open(log_file, 'a') as f: f.write("Error Type: TimeoutExpired\n")
         except IOError: pass
         return None
     except Exception as e:
         print_error(f"An unexpected error occurred during query execution: {str(e)}")
         if process: process.kill()
         try:
             with open(log_file, 'a') as f: f.write(f"Error Type: Unexpected Exception\nException: {str(e)}\n")
         except IOError: pass
         return None
     finally:
         # Clean up temporary file
         if os.path.exists(temp_query_file):
             try:
                 os.remove(temp_query_file)
                 # print_info(f"Cleaned up temporary file: {temp_query_file}")
             except OSError as e:
                 print_warning(f"Could not remove temporary file {temp_query_file}: {e}")

def generate_simple_kql_query(target_ip: str, time_range_hours: int = 24) -> str:
    """Generate a simple KQL query without NSG filtering"""
    end_time = datetime.now(timezone.utc)
    start_time = end_time - timedelta(hours=time_range_hours)
    
    start_time_str = start_time.strftime("%Y-%m-%dT%H:%M:%S.%f")[:23] + "Z"
    end_time_str = end_time.strftime("%Y-%m-%dT%H:%M:%S.%f")[:23] + "Z"
    
    # KQL query targeting only AzureNetworkAnalytics_CL based on provided correct format
    query = f"""
// KQL Query Parameters: IP={target_ip}, Time Range={time_range_hours} hours
AzureNetworkAnalytics_CL
| where TimeGenerated between (datetime({start_time_str}) .. datetime({end_time_str}))
| where FlowStatus_s == "A" // Assuming 'A' means Allowed/Accepted flow
| where SrcIP_s == "{target_ip}" or DestIP_s == "{target_ip}"
| project
    TimeGenerated,
    FlowDirection_s,
    SrcIP_s,
    DestIP_s,
    SrcPort_d,
    DestPort_d,
    Protocol_s,
    FlowStatus_s,
    L7Protocol_s,
    InboundBytes_d,
    OutboundBytes_d
| sort by TimeGenerated desc
| limit 100 // Limit results for performance
"""
    return query

def generate_kql_query(target_ip: str, 
                      flow_logs_config: Dict[str, Dict], 
                      workspace_ids: Dict[str, str],
                      time_range_hours: int = 24,
                      filter_by_nsg: bool = True) -> Dict[str, str]:
    """Generate KQL queries for each workspace"""
    output_dir = "output"
    os.makedirs(output_dir, exist_ok=True)
    
    kql_queries = {}
    end_time = datetime.now(timezone.utc)
    start_time = end_time - timedelta(hours=time_range_hours)
    
    start_time_str = start_time.strftime("%Y-%m-%dT%H:%M:%S.%f")[:23] + "Z"
    end_time_str = end_time.strftime("%Y-%m-%dT%H:%M:%S.%f")[:23] + "Z"
    
    workspace_to_nsgs = {}
    for nsg_id, workspace_id in workspace_ids.items():
        if workspace_id not in workspace_to_nsgs:
            workspace_to_nsgs[workspace_id] = []
        workspace_to_nsgs[workspace_id].append(nsg_id)
    
    for workspace_id, nsg_ids in workspace_to_nsgs.items():
        nsg_names_str = ""
        
        # KQL query targeting only AzureNetworkAnalytics_CL based on provided correct format
        query = f"""
// KQL Query Parameters: IP={target_ip}, Time Range={time_range_hours} hours, NSG Filter Applied={filter_by_nsg and bool(nsg_names_str)}
AzureNetworkAnalytics_CL
| where TimeGenerated between (datetime({start_time_str}) .. datetime({end_time_str}))
| where FlowStatus_s == "A" // Assuming 'A' means Allowed/Accepted flow
| where SrcIP_s == "{target_ip}" or DestIP_s == "{target_ip}"
| project
    TimeGenerated,
    FlowDirection_s,
    SrcIP_s,
    DestIP_s,
    DestPort_d,
    Protocol_s,
    FlowStatus_s,
    L7Protocol_s,
    InboundBytes_d,
    OutboundBytes_d
| sort by TimeGenerated desc
| limit 100 // Limit results for performance
"""
        workspace_short_id = workspace_id.split('/')[-1] if '/' in workspace_id else workspace_id
        query_filename = f"kql_query_{workspace_short_id}.kql"
        query_path = os.path.join(output_dir, query_filename)
        
        with open(query_path, 'w', encoding='utf-8') as f:
            f.write(query)
        
        kql_queries[workspace_id] = query
    
    return kql_queries

def analyze_traffic(target_ip: str, time_range_hours: int = 24, filter_by_nsg: bool = True, execute_query: bool = False, timeout_seconds: int = 60) -> Dict[str, Any]:
    """Main function to analyze traffic for an IP address"""
    output_dir = "output"
    os.makedirs(output_dir, exist_ok=True)
    
    results = {
        "target_ip": target_ip,
        "time_range_hours": time_range_hours,
        "timestamp": datetime.now(timezone.utc).isoformat(),
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
                with open(result_path, 'w', encoding='utf-8') as f:
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
                with open(result_path, 'w', encoding='utf-8') as f:
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
                with open(result_path, 'w', encoding='utf-8') as f:
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
        with open(result_path, 'w', encoding='utf-8') as f:
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
        with open(result_path, 'w', encoding='utf-8') as f:
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
                    with open(result_path, 'w', encoding='utf-8') as f:
                        f.write(query)
                    print_success(f"Generated KQL query and saved to {result_path}")
                    
                    if input("\nDo you want to execute this query now? (y/n): ").lower().strip() == 'y':
                        results = execute_kql_query(workspace_id, query, args.timeout)
                        save_json(results or {}, os.path.join(output_dir, "direct_query_results.json"))
    
if __name__ == "__main__":
    main()
