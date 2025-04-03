import os
import sys
import json
import argparse
import subprocess
import ipaddress
import re
import logging
from datetime import datetime, timedelta, timezone
from typing import List, Dict, Any, Optional, Tuple
import pandas as pd # 添加 pandas 导入

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
    # Ensure output directory exists
    output_dir = os.path.dirname(file_path)
    if output_dir: # Avoid error if saving to current directory
        os.makedirs(output_dir, exist_ok=True)
    try:
        with open(file_path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2)
        print_info(f"Saved data to {file_path}")
    except IOError as e:
        print_error(f"Failed to save JSON to {file_path}: {e}")
    except TypeError as e:
        print_error(f"Data is not JSON serializable for {file_path}: {e}")


def run_command(cmd: str) -> Optional[Dict]:
    """Run command and return JSON result"""
    try:
        print_info(f"Executing command: {cmd}")
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, check=False, encoding='utf-8') # Specify encoding

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
            print_info(f"Command output (non-JSON): {result.stdout[:500]}...") # Show preview
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
        print_warning(f"Error parsing IP or subnet prefix '{subnet_prefix}': {str(e)}")
        return False

def find_nsgs_by_ip(target_ip: str) -> List[str]:
    """Find list of NSG IDs associated with an IP"""
    print_info(f"\nFinding NSGs associated with IP {target_ip}...")
    nsg_ids = []
    output_dir = "output"
    os.makedirs(output_dir, exist_ok=True)

    # 1. Find network interfaces directly using this IP
    print_info("\nStep 1: Finding network interfaces directly using this IP...")
    # Use Azure Resource Graph query for efficiency
    nic_cmd = f"az graph query -q \"Resources | where type =~ 'microsoft.network/networkinterfaces' | where properties.ipConfigurations contains '{target_ip}' | project id, name, resourceGroup, subnetId = tostring(properties.ipConfigurations[0].properties.subnet.id), nsgId = tostring(properties.networkSecurityGroup.id)\" --query \"data\" -o json"

    nics = run_command(nic_cmd)
    if nics and isinstance(nics, list): # Ensure nics is a list
        save_json(nics, os.path.join(output_dir, f"network_interfaces_{target_ip}.json"))
        print_success(f"Found {len(nics)} network interfaces potentially associated with IP {target_ip}")

        # 1.1 Collect NSGs directly associated with NICs
        nic_subnet_ids = set() # Use a set for unique subnet IDs
        for nic in nics:
            # Verify IP match more accurately if possible (Graph query might be broad)
            # This part might need refinement depending on exact 'ipConfigurations' structure
            ip_match = False
            if 'properties' in nic and 'ipConfigurations' in nic['properties']:
                 for ip_config in nic['properties'].get('ipConfigurations', []):
                     if ip_config.get('properties', {}).get('privateIPAddress') == target_ip:
                         ip_match = True
                         break
            # For now, assume the graph query is accurate enough or proceed cautiously

            nsg_id = nic.get('nsgId')
            if nsg_id and nsg_id not in nsg_ids:
                nsg_ids.append(nsg_id)
                print_success(f"Found NSG from network interface '{nic.get('name')}': {nsg_id}")

            # 1.2 Get subnet IDs from network interfaces
            subnet_id = nic.get('subnetId') # Use the projected subnetId
            if subnet_id:
                nic_subnet_ids.add(subnet_id)

        # 2. Get NSGs associated with the subnets found via NICs
        print_info(f"\nStep 2: Checking subnets associated with found NICs ({len(nic_subnet_ids)} unique subnets)...")
        for subnet_id in nic_subnet_ids:
            print_info(f"Checking subnet: {subnet_id}")
            # Extract VNET name and subnet name from subnet ID
            parts = subnet_id.split('/')
            resource_group = None
            vnet_name = None
            subnet_name = None

            try: # Add error handling for parsing
                for i, part in enumerate(parts):
                    if part.lower() == 'resourcegroups' and i+1 < len(parts):
                        resource_group = parts[i+1]
                    elif part.lower() == 'virtualnetworks' and i+1 < len(parts):
                        vnet_name = parts[i+1]
                    elif part.lower() == 'subnets' and i+1 < len(parts):
                        subnet_name = parts[i+1]
            except Exception as e:
                 print_warning(f"Could not parse subnet ID {subnet_id}: {e}")
                 continue # Skip to next subnet ID

            if resource_group and vnet_name and subnet_name:
                print_info(f"Subnet info parsed: RG={resource_group}, VNET={vnet_name}, Subnet={subnet_name}")

                # Get detailed subnet information directly from Azure
                subnet_cmd = f"az network vnet subnet show --resource-group \"{resource_group}\" --vnet-name \"{vnet_name}\" --name \"{subnet_name}\" -o json"
                subnet_details = run_command(subnet_cmd)

                if subnet_details:
                    save_json(subnet_details, os.path.join(output_dir, f"subnet_{subnet_name}_{target_ip}.json"))

                    # Extract NSG associated with the subnet
                    subnet_nsg = subnet_details.get('networkSecurityGroup', {})
                    if isinstance(subnet_nsg, dict) and 'id' in subnet_nsg:
                        subnet_nsg_id = subnet_nsg['id']
                        if subnet_nsg_id and subnet_nsg_id not in nsg_ids:
                            nsg_ids.append(subnet_nsg_id)
                            print_success(f"Found NSG from subnet '{subnet_name}': {subnet_nsg_id}")
                        elif subnet_nsg_id:
                             print_info(f"NSG from subnet '{subnet_name}' already recorded.")
                    else:
                        print_info(f"Subnet '{subnet_name}' has no directly associated NSG.")
            else:
                 print_warning(f"Could not fully parse subnet ID: {subnet_id}")

    else:
        print_warning(f"No network interfaces found directly associated with IP {target_ip} via Graph query.")

    # 3. If no direct NIC found or to be comprehensive, find subnets containing this IP range
    print_info("\nStep 3: Searching all subnets for IP range containment...")

    # Query all subnets using Azure Resource Graph
    subnets_cmd = "az graph query -q \"Resources | where type =~ 'microsoft.network/virtualnetworks/subnets' | project id, name, resourceGroup, vnetName = split(id, '/')[8], addressPrefix = properties.addressPrefix, addressPrefixes = properties.addressPrefixes, nsgId = tostring(properties.networkSecurityGroup.id)\" --query \"data\" -o json"

    all_subnets = run_command(subnets_cmd)
    if all_subnets and isinstance(all_subnets, list): # Ensure it's a list
        save_json(all_subnets, os.path.join(output_dir, f"all_subnets_{target_ip}.json"))
        print_success(f"Found {len(all_subnets)} subnets in total to check.")

        # Check each subnet to see if it contains this IP
        found_in_subnet = False
        for subnet in all_subnets:
            subnet_name = subnet.get('name', 'UnknownSubnet')
            # Combine addressPrefix and addressPrefixes
            prefixes = []
            if subnet.get('addressPrefix'):
                prefixes.append(subnet['addressPrefix'])
            if isinstance(subnet.get('addressPrefixes'), list):
                prefixes.extend(subnet['addressPrefixes'])

            if not prefixes:
                 # print_warning(f"Subnet {subnet_name} has no address prefix information.")
                 continue # Skip subnets without prefix info

            for prefix in set(prefixes): # Use set to avoid duplicate checks
                if prefix and ip_in_subnet(target_ip, prefix):
                    found_in_subnet = True
                    print_success(f"IP {target_ip} is within subnet '{subnet_name}' range {prefix}")

                    # Get NSG associated with the subnet
                    nsg_id = subnet.get('nsgId')
                    if nsg_id and nsg_id not in nsg_ids:
                        nsg_ids.append(nsg_id)
                        print_success(f"Found NSG from subnet '{subnet_name}': {nsg_id}")
                    elif nsg_id:
                        print_info(f"NSG from subnet '{subnet_name}' already recorded.")
                    else:
                        print_info(f"Subnet '{subnet_name}' containing the IP has no directly associated NSG.")
                    # No need to get full subnet details again if already processed via NICs
                    break # Stop checking prefixes for this subnet once a match is found
    else:
        print_warning("Unable to get the list of all subnets via Graph query.")

    # Save all unique NSG IDs found
    unique_nsg_ids = list(set(nsg_ids)) # Ensure uniqueness
    if unique_nsg_ids:
        save_json(unique_nsg_ids, os.path.join(output_dir, f"nsg_ids_found_{target_ip}.json"))
        print_success(f"\nTotal unique NSGs potentially related to IP {target_ip}: {len(unique_nsg_ids)}")
        for i, nsg_id in enumerate(unique_nsg_ids):
            print(f"  {i+1}. {nsg_id}")
    else:
        print_warning(f"\nNo NSGs found potentially related to IP {target_ip}")

    return unique_nsg_ids

def get_nsg_flow_logs_config(nsg_ids: List[str], target_ip: str) -> Dict[str, Dict]:
    """Get flow logs configuration for NSGs"""
    print_info("\nStep 4: Getting NSG flow logs configuration...")
    output_dir = "output"
    # No need for os.makedirs here, find_nsgs_by_ip should have created it

    flow_logs_config = {}

    for nsg_id in nsg_ids:
        # Extract resource group and NSG name from NSG ID
        parts = nsg_id.split('/')
        resource_group = None
        nsg_name = None

        try: # Add error handling
            for i, part in enumerate(parts):
                if part.lower() == 'resourcegroups' and i+1 < len(parts):
                    resource_group = parts[i+1]
                elif part.lower() == 'networksecuritygroups' and i+1 < len(parts):
                    nsg_name = parts[i+1]
        except Exception as e:
            print_warning(f"Could not parse NSG ID {nsg_id}: {e}")
            continue

        if not resource_group or not nsg_name:
            print_warning(f"Unable to extract resource group and NSG name from NSG ID: {nsg_id}")
            continue

        print_info(f"Getting flow logs configuration for NSG '{nsg_name}'...")

        # Use Resource Graph to query for flow logs targeting this NSG
        # Query includes workspace ID directly if available
        flow_logs_cmd = f"az graph query -q \"Resources | where type =~ 'Microsoft.Network/networkWatchers/flowLogs' | where properties.targetResourceId =~ '{nsg_id}' | project id, name, resourceGroup, flowLogResourceId=id, workspaceId=properties.flowAnalyticsConfiguration.networkWatcherFlowAnalyticsConfiguration.workspaceId, enabled=properties.enabled, retentionDays=properties.retentionPolicy.days\" --query \"data\" -o json"

        flow_logs_list = run_command(flow_logs_cmd)

        if flow_logs_list and isinstance(flow_logs_list, list):
            if len(flow_logs_list) > 0:
                # Assuming the first result is the relevant one if multiple exist
                config_data = flow_logs_list[0]
                flow_logs_config[nsg_id] = config_data
                print_success(f"Found flow logs configuration for NSG '{nsg_name}'. Enabled: {config_data.get('enabled')}")
                save_json(config_data, os.path.join(output_dir, f"flow_logs_{nsg_name}_{target_ip}.json"))

                # Check if workspace ID is present
                if not config_data.get('workspaceId'):
                     print_warning(f"Flow log config found for NSG '{nsg_name}', but workspace ID is missing in the config. Traffic Analytics might be disabled or using a different setup.")
            else:
                print_warning(f"NSG '{nsg_name}' has no associated flow logs resource found via Graph query.")
        else:
            print_warning(f"Could not retrieve flow logs configuration for NSG '{nsg_name}' via Graph query or result format unexpected.")
            # Optional: Add fallback logic here if needed, e.g., trying `az network nsg show`
            # and parsing, but Graph is generally preferred.

    # Save all found flow logs configurations together
    if flow_logs_config:
        save_json(flow_logs_config, os.path.join(output_dir, f"flow_logs_config_all_{target_ip}.json"))
        print_success(f"Saved flow logs configuration summary for {len(flow_logs_config)} NSGs.")
    else:
        print_warning("No NSG flow logs configuration found for any provided NSG ID.")

    return flow_logs_config

def get_log_analytics_workspaces(flow_logs_config: Dict[str, Dict], target_ip: str) -> Dict[str, str]:
    """Extract Log Analytics workspace IDs from flow logs configuration"""
    print_info("\nStep 5: Extracting Log Analytics workspace information...")
    workspace_ids = {} # Maps NSG ID to Workspace ID
    output_dir = "output"

    for nsg_id, config in flow_logs_config.items():
        nsg_name = nsg_id.split('/')[-1] # For logging
        workspace_id = None

        # Extract workspace ID directly from the Graph query result
        if isinstance(config, dict):
            workspace_id = config.get('workspaceId')

        if workspace_id:
            # Validate workspace ID format - accept full Resource ID or just GUID
            is_guid_format = len(workspace_id) == 36 and workspace_id.count('-') == 4
            is_full_id_format = '/subscriptions/' in workspace_id and '/workspaces/' in workspace_id

            if is_full_id_format or is_guid_format:
                workspace_ids[nsg_id] = workspace_id # Store whatever format we received
                print_success(f"Log Analytics workspace ID for NSG '{nsg_name}': {workspace_id}")
            else:
                # Log if it's neither expected format
                print_warning(f"Unexpected workspace ID format found for NSG '{nsg_name}': {workspace_id}")
        else:
            # This case was already warned about in get_nsg_flow_logs_config
            print_info(f"No valid workspace ID found in the configuration for NSG '{nsg_name}'. Skipping KQL query for this NSG.")

    # Save workspace IDs mapping
    if workspace_ids:
        save_json(workspace_ids, os.path.join(output_dir, f"workspace_ids_map_{target_ip}.json"))
        print_success(f"Found {len(workspace_ids)} Log Analytics workspace IDs to query.")
    else:
        print_warning("No Log Analytics workspace IDs found to query.")

    return workspace_ids

def setup_logger(log_file_path: str):
    """配置日志记录器"""
    logger = logging.getLogger(log_file_path) # Use file path as logger name to avoid conflicts
    if logger.hasHandlers(): # Return existing logger if already configured
        # Ensure level is still appropriate if re-retrieved
        logger.setLevel(logging.INFO)
        for handler in logger.handlers:
             if isinstance(handler, logging.FileHandler):
                 handler.setLevel(logging.INFO)
             elif isinstance(handler, logging.StreamHandler):
                 handler.setLevel(logging.WARNING)
        return logger

    logger.setLevel(logging.INFO) # Set minimum level for the logger

    # Ensure log directory exists
    log_dir = os.path.dirname(log_file_path)
    if log_dir:
        os.makedirs(log_dir, exist_ok=True)

    # Create file handler (INFO and above)
    try:
        fh = logging.FileHandler(log_file_path, encoding='utf-8')
        fh.setLevel(logging.INFO)
        # Create console handler (WARNING and above)
        ch = logging.StreamHandler()
        ch.setLevel(logging.WARNING)
        # Define formatter
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        fh.setFormatter(formatter)
        ch.setFormatter(formatter)
        # Add handlers
        logger.addHandler(fh)
        logger.addHandler(ch)
    except Exception as e:
        print_error(f"Failed to configure logging to {log_file_path}: {e}")
        # Fallback to basic console logging if file setup fails
        logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
        logger = logging.getLogger("fallback_logger") # Get the fallback logger

    return logger

def execute_kql_query(workspace_id: str, kql_query: str, target_ip: str, nsg_id: str, timeout_seconds: int = 180) -> Optional[Dict]:
    """Execute a KQL query against a Log Analytics workspace, save results to Excel, and log execution."""

    # --- 日志配置 ---
    output_dir = "output"
    log_dir = os.path.join(output_dir, "logs")
    # Log file name based on IP and Date
    log_file_name = f"query_log_{target_ip.replace('.', '_')}_{datetime.now().strftime('%Y%m%d')}.log"
    log_file_path = os.path.join(log_dir, log_file_name)
    # Use NSG ID in logger name for uniqueness if multiple queries run in parallel/quick succession
    # logger_name = f"{log_file_path}_{nsg_id.split('/')[-1]}" # Using file path is sufficient
    logger = setup_logger(log_file_path) # Setup ensures directory exists

    nsg_name = nsg_id.split('/')[-1] # For logging clarity
    logger.info(f"--- Starting KQL Query Execution ---")
    logger.info(f"Target IP: {target_ip}")
    logger.info(f"NSG Name: {nsg_name}")
    logger.info(f"Workspace ID: {workspace_id}")
    logger.info(f"Timeout Seconds: {timeout_seconds}")

    # --- KQL 查询准备 ---
    kql_query = kql_query.strip()
    logger.debug(f"KQL Query:\n{kql_query}") # Log full query at debug level

    # Make sure workspace ID is just the ID, not the full resource path
    if '/' in workspace_id:
        workspace_short_id = workspace_id.split('/')[-1]
        logger.info(f"Using Workspace ID (short): {workspace_short_id}")
    else:
        workspace_short_id = workspace_id # Assume it's already the short ID

    # Create a temporary file for the query
    temp_query_dir = os.path.join(output_dir, "temp_queries")
    os.makedirs(temp_query_dir, exist_ok=True)
    timestamp = datetime.now().strftime('%Y%m%d%H%M%S%f')
    temp_query_file = os.path.join(temp_query_dir, f"temp_query_{target_ip}_{nsg_name}_{timestamp}.kql")

    try:
        with open(temp_query_file, 'w', encoding='utf-8') as f:
            f.write(kql_query)
        logger.info(f"Temporary query file created: {temp_query_file}")
    except IOError as e:
        logger.error(f"Failed to write temporary query file {temp_query_file}: {e}")
        print_error(f"Failed to write temporary query file {temp_query_file}: {e}")
        return None

    # Construct Azure CLI command
    # Use workspace short ID for the command
    cmd = f"az monitor log-analytics query --workspace \"{workspace_short_id}\" --analytics-query \"@{temp_query_file}\" -o json"
    logger.info(f"Executing Azure CLI command (using temp file): {cmd}")
    print_info(f"Executing KQL query for NSG '{nsg_name}' via Azure CLI (using temp file)...")

    # Execute the query
    stdout, stderr = "", ""
    process = None
    results = None
    try:
        process = subprocess.Popen(
            cmd,
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding='utf-8'
        )

        # Wait with timeout (use provided timeout, add buffer for CLI overhead)
        cli_timeout = timeout_seconds + 60 # Add 60s buffer for CLI startup/JSON parsing etc.
        logger.info(f"Waiting for command with timeout: {cli_timeout} seconds")
        stdout, stderr = process.communicate(timeout=cli_timeout)

        logger.info(f"Command Return Code: {process.returncode}")
        if stderr:
            # Log entire stderr for debugging potential issues like auth prompts
            logger.warning(f"Command Stderr:\n{stderr}")
        # Log stdout preview only if needed for debugging, can be large
        # stdout_preview = stdout[:1000] + ('...' if len(stdout) > 1000 else '')
        # logger.debug(f"Command StdOut Preview: {stdout_preview}")

        # --- Process Results ---
        if process.returncode != 0:
            # Handle specific errors based on stderr content
            if "ResponseSizeError" in stderr or "Response size too large" in stderr:
                error_msg = f"Query result for NSG '{nsg_name}' exceeded maximum size limit. Consider reducing time range or using batching."
                logger.error(error_msg)
                logger.error(f"Stderr detail: {stderr}")
                print_error(error_msg)
            elif "SemanticError" in stderr:
                error_msg = f"KQL Semantic Error for workspace '{workspace_short_id}' (NSG '{nsg_name}'). Check table/field names."
                logger.error(error_msg)
                logger.error(f"Stderr detail: {stderr}")
                print_error(error_msg)
                print_error("Verify table/field names (e.g., AzureNetworkAnalytics_CL) exist in this workspace.")
                print_error(f"See details in log file: {log_file_path}")
            elif "AuthenticationFailed" in stderr or "AuthorizationFailed" in stderr or "Please run 'az login'" in stderr:
                error_msg = f"Authentication/Authorization Failed for workspace '{workspace_short_id}' (NSG '{nsg_name}'). Check Azure login ('az login') and permissions."
                logger.error(error_msg)
                logger.error(f"Stderr detail: {stderr}")
                print_error(error_msg)
                print_error(f"See details in log file: {log_file_path}")
            elif "timed out" in stderr.lower(): # Check stderr for timeout messages from az cli itself
                 error_msg = f"Azure CLI command itself may have timed out internally for NSG '{nsg_name}'."
                 logger.error(error_msg)
                 logger.error(f"Stderr detail: {stderr}")
                 print_error(error_msg)
            else:
                # Generic error
                error_msg = f"Query execution failed for NSG '{nsg_name}' with return code {process.returncode}."
                logger.error(error_msg)
                logger.error(f"Stderr: {stderr}") # Log full stderr for generic errors
                print_error(f"{error_msg} See details in log file: {log_file_path}")
            return None # Return None on any execution error

        # Check if stdout is empty even on success
        if not stdout or not stdout.strip():
            logger.warning(f"Query for NSG '{nsg_name}' executed successfully but returned no data.")
            print_warning(f"Query for NSG '{nsg_name}' executed successfully but returned no data.")
            return {"tables": []} # Return structure expected by downstream processing

        # Try parsing the JSON result
        try:
            results = json.loads(stdout)
            # Basic validation
            if not isinstance(results, dict) or 'tables' not in results:
                 logger.warning(f"Query for NSG '{nsg_name}' returned unexpected JSON structure. Raw output saved.")
                 print_warning(f"Query for NSG '{nsg_name}' returned unexpected JSON structure. Raw output saved.")
                 raw_output_path = os.path.join(output_dir, f"query_results_{target_ip}_{nsg_name}_{timestamp}_raw.txt")
                 try:
                     with open(raw_output_path, 'w', encoding='utf-8') as rf: rf.write(stdout)
                     logger.info(f"Raw output saved to {raw_output_path}")
                     print_info(f"Raw output saved to {raw_output_path}")
                 except IOError as e:
                     logger.warning(f"Could not save raw output: {e}")
                     print_warning(f"Could not save raw output: {e}")
                 return {"tables": []} # Return empty structure

            # --- Save Results (JSON and Excel) ---
            base_filename = f"query_results_{target_ip.replace('.', '_')}_{nsg_name}_{timestamp}"
            result_file_dir = os.path.join(output_dir, "query_results") # Subdirectory for results
            os.makedirs(result_file_dir, exist_ok=True)

            # Save original JSON results
            json_result_path = os.path.join(result_file_dir, f"{base_filename}.json")
            save_json(results, json_result_path) # Use the existing save_json function
            logger.info(f"JSON results saved to {json_result_path}")

            # Process and save to Excel
            result_count = 0
            if isinstance(results.get('tables'), list) and len(results['tables']) > 0:
                 table = results['tables'][0]
                 if isinstance(table.get('rows'), list):
                     result_count = len(table['rows'])

                 logger.info(f"Query for NSG '{nsg_name}' returned {result_count} records.")
                 print_success(f"Query for NSG '{nsg_name}' returned {result_count} records.")

                 if result_count > 0:
                     try:
                         columns = [col['name'] for col in table['columns']]
                         rows = table['rows']
                         df = pd.DataFrame(rows, columns=columns)

                         excel_result_path = os.path.join(result_file_dir, f"{base_filename}.xlsx")
                         # Ensure excel engine is available
                         try:
                             import openpyxl
                         except ImportError:
                              logger.error("Module 'openpyxl' not found. Cannot save to Excel. Run: pip install openpyxl")
                              print_error("Module 'openpyxl' not found. Cannot save to Excel. Please install it.")
                              # Still return results, just skip Excel saving
                              return results

                         df.to_excel(excel_result_path, index=False, engine='openpyxl')
                         logger.info(f"Excel results saved to {excel_result_path}")
                         print_success(f"Excel results saved to {excel_result_path}")

                         # Print sample records (from DataFrame)
                         print_info("Sample records (up to 3):")
                         print(df.head(3).to_string())

                     except ImportError:
                         # This case handles pandas import error, though it's imported at the top
                         logger.warning("Pandas not installed? Cannot save to Excel. Please install: pip install pandas")
                         print_warning("Pandas not installed? Cannot save to Excel.")
                     except Exception as e:
                         logger.error(f"Error saving results to Excel for NSG '{nsg_name}': {e}")
                         print_error(f"Error saving results to Excel for NSG '{nsg_name}': {e}")
                 else:
                      logger.info(f"No records found for NSG '{nsg_name}' to save to Excel.")
            else:
                 logger.warning(f"Query result for NSG '{nsg_name}' has no 'tables' array or is not a list.")
                 print_warning(f"Query result for NSG '{nsg_name}' has an unexpected structure (no tables/rows).")


            return results # Return the parsed results

        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse query results as JSON for NSG '{nsg_name}': {e}")
            logger.info(f"Raw output preview: {stdout[:500]}...")
            print_error(f"Failed to parse query results as JSON for NSG '{nsg_name}': {e}")
            # Save raw output for debugging
            raw_output_path = os.path.join(output_dir, f"query_results_{target_ip}_{nsg_name}_{timestamp}_raw.txt")
            try:
                with open(raw_output_path, 'w', encoding='utf-8') as rf: rf.write(stdout)
                logger.info(f"Raw output saved to {raw_output_path}")
                print_info(f"Raw output saved to {raw_output_path}")
            except IOError as ioe:
                logger.warning(f"Could not save raw output: {ioe}")
                print_warning(f"Could not save raw output: {ioe}")
            return None # Indicate failure

    except subprocess.TimeoutExpired:
        error_msg = f"Command timed out after {cli_timeout} seconds for NSG '{nsg_name}'."
        logger.error(error_msg)
        print_error(error_msg)
        if process:
            process.kill() # Ensure process is terminated
            logger.info("Killed timed-out process.")
        return None
    except Exception as e:
        error_msg = f"An unexpected error occurred during query execution for NSG '{nsg_name}': {e}"
        logger.exception(error_msg) # Log exception with traceback
        print_error(error_msg)
        return None
    finally:
        # Clean up temporary query file
        if 'temp_query_file' in locals() and os.path.exists(temp_query_file):
            try:
                os.remove(temp_query_file)
                logger.info(f"Removed temporary query file: {temp_query_file}")
            except OSError as e:
                logger.warning(f"Could not remove temporary query file {temp_query_file}: {e}")

    # This part should ideally not be reached if results are returned within the try block
    return results # Should contain the parsed data if successful


def generate_simple_kql_query(target_ip: str, time_range_hours: int = 24) -> str:
    """Generates a basic KQL query for NSG flow logs (AzureNetworkAnalytics_CL)."""
    # Default table name, adjust if needed
    table_name = "AzureNetworkAnalytics_CL"
    # Time range calculation
    end_time = datetime.now(timezone.utc)
    start_time = end_time - timedelta(hours=time_range_hours)
    start_time_str = start_time.strftime('%Y-%m-%dT%H:%M:%SZ')
    end_time_str = end_time.strftime('%Y-%m-%dT%H:%M:%SZ')

    # Basic query structure
    query = f"""
{table_name}
| where TimeGenerated between (datetime('{start_time_str}') .. datetime('{end_time_str}'))
| where FlowType_s == "AzureNetworkAnalytics" // Ensure we are looking at flow logs
| where SrcIP_s == "{target_ip}" or DestIP_s == "{target_ip}"
// Add more fields as needed
| project TimeGenerated, FlowStartTime_t, SrcIP_s, SrcPort_d, DestIP_s, DestPort_d, Protocol_s, FlowDirection_s, FlowStatus_s, NSGList_s, NSGRule_s, NetworkIntent_s, L7Protocol_s, DestPublicIPs_s, DestPrivateIPs_s, InboundBytes_d, OutboundBytes_d, InboundPackets_d, OutboundPackets_d
| order by TimeGenerated desc
// | take 100 // Optional: Limit results during testing
"""
    return query.strip()


def generate_kql_query(target_ip: str,
                       time_range_hours: int = 24, # Keep for default case
                       nsg_id: Optional[str] = None,
                       start_time_dt: Optional[datetime] = None,
                       end_time_dt: Optional[datetime] = None) -> str:
    """
    Generates a KQL query for NSG flow logs (AzureNetworkAnalytics_CL),
    optionally filtering by a specific NSG ID and allowing specific time windows.
    """
    table_name = "AzureNetworkAnalytics_CL" # Common table for NSG Flow Logs v2 with Traffic Analytics

    # Determine time range
    if start_time_dt is None or end_time_dt is None:
        # Default to time_range_hours if specific datetimes are not provided
        end_time = datetime.now(timezone.utc)
        start_time = end_time - timedelta(hours=time_range_hours)
    else:
        start_time = start_time_dt
        end_time = end_time_dt

    # Format times for KQL
    start_time_str = start_time.strftime('%Y-%m-%dT%H:%M:%SZ')
    end_time_str = end_time.strftime('%Y-%m-%dT%H:%M:%SZ')

    # Build the query parts
    query_parts = [
        table_name,
        f"| where TimeGenerated between (datetime('{start_time_str}') .. datetime('{end_time_str}'))", # Use quotes for datetime strings
        f'| where FlowStatus_s == "A"', # Filter for Allowed flows like the successful query screenshot
        f'| where SrcIP_s == "{target_ip}" or DestIP_s == "{target_ip}"'
    ]

    # Add NSG filter if provided
    if nsg_id:
        # NSGList_s usually contains the NSG name, not the full ID. Extract name.
        try:
            nsg_name = nsg_id.split('/')[-1]
            query_parts.append(f'| where NSGList_s contains "{nsg_name}"') # Use 'contains' for flexibility
        except Exception:
             print_warning(f"Could not extract NSG name from ID '{nsg_id}' for query filter.")


    # Add projection and ordering (matching successful query screenshot exactly)
    query_parts.extend([
        "| project TimeGenerated, FlowDirection_s, SrcIP_s, DestIP_s, DestPort_d, Protocol_s, FlowStatus_s, L7Protocol_s, InboundBytes_d, OutboundBytes_d",
        "| order by TimeGenerated desc" # Use 'order by' instead of 'sort by' if needed, KQL usually accepts both but 'order by' is common
        # "| take 10000" # Consider adding a limit if not batching or for testing
    ])

    # Join parts into a single query string
    full_query = "\n".join(query_parts)
    return full_query.strip()


def analyze_traffic(target_ip: str, time_range_hours: int = 24, filter_by_nsg: bool = True, execute_query: bool = False, timeout_seconds: int = 180, query_batch_hours: Optional[int] = None) -> Dict[str, Any]:
    """
    Main analysis function: Finds NSGs, gets configs, generates and executes KQL queries.
    """
    print_info(f"\n===== Starting Traffic Analysis for IP: {target_ip} =====")
    analysis_summary = {
        "target_ip": target_ip,
        "time_range_hours": time_range_hours,
        "filter_by_nsg": filter_by_nsg,
        "execute_query": execute_query,
        "query_batch_hours": query_batch_hours,
        "nsgs_found": [],
        "flow_logs_config": {},
        "workspaces_queried": {}, # workspace_id: [nsg_ids]
        "query_results": {}, # nsg_id: {"status": "...", "total_records": ..., "batches_failed": ..., "last_error": "..."}
        "errors": []
    }

    # Phase 1: Find NSGs related to the IP
    print_info("\n===== Phase 1: Finding related NSGs =====")
    nsg_ids = find_nsgs_by_ip(target_ip)
    analysis_summary["nsgs_found"] = nsg_ids
    if not nsg_ids:
        print_warning("No NSGs found. Analysis cannot proceed further for KQL queries.")
        return analysis_summary # Return early if no NSGs

    # Phase 2: Get Flow Log Configuration for found NSGs
    print_info("\n===== Phase 2: Getting Flow Log Configurations =====")
    flow_logs_config = get_nsg_flow_logs_config(nsg_ids, target_ip)
    analysis_summary["flow_logs_config"] = flow_logs_config
    if not flow_logs_config:
        print_warning("No flow log configurations found for the NSGs. Cannot determine workspaces.")
        # We might still have NSG info, but can't query logs
        return analysis_summary

    # Phase 3: Identify Log Analytics Workspaces
    print_info("\n===== Phase 3: Identifying Log Analytics Workspaces =====")
    workspace_map = get_log_analytics_workspaces(flow_logs_config, target_ip) # Map NSG ID -> Workspace ID
    if not workspace_map:
        print_warning("No Log Analytics workspaces identified from flow log configs. Cannot execute KQL queries.")
        return analysis_summary

    # Group NSGs by Workspace ID for efficient querying
    workspaces_to_query = {} # workspace_id: [nsg_ids]
    for nsg_id, ws_id in workspace_map.items():
        if ws_id not in workspaces_to_query:
            workspaces_to_query[ws_id] = []
        workspaces_to_query[ws_id].append(nsg_id)
    analysis_summary["workspaces_queried"] = workspaces_to_query

    # Phase 4: Generate and Execute KQL Queries (if requested)
    print_info("\n===== Phase 4: Generating and Executing KQL Queries =====")
    if not execute_query:
        print_warning("Query execution skipped as per '--no-execute' flag.")
        # Generate sample queries for user reference
        for workspace_id, nsg_list in workspaces_to_query.items():
            # Generate query for the first NSG in the list for this workspace as an example
            example_nsg_id = nsg_list[0]
            kql_query = generate_kql_query(
                target_ip=target_ip,
                time_range_hours=time_range_hours, # Use full range for sample
                nsg_id=example_nsg_id if filter_by_nsg else None
            )
            print_info(f"\nSample KQL Query for Workspace {workspace_id.split('/')[-1]} (NSG: {example_nsg_id.split('/')[-1]}):")
            print(kql_query)
            # Save sample query
            query_file = os.path.join("output", f"sample_query_{target_ip}_{example_nsg_id.split('/')[-1]}.kql")
            try:
                with open(query_file, 'w', encoding='utf-8') as f: f.write(kql_query)
                print_info(f"Sample query saved to {query_file}")
            except IOError as e:
                print_warning(f"Could not save sample query: {e}")

        return analysis_summary

    # Execute queries
    print_info("Executing KQL queries...")
    all_results_df = [] # List to hold DataFrames from successful queries
    query_execution_errors = 0 # Counter for failed queries

    # Determine overall time range
    overall_end_time = datetime.now(timezone.utc)
    overall_start_time = overall_end_time - timedelta(hours=time_range_hours)

    for workspace_id, nsg_list in workspaces_to_query.items():
        ws_short_id = workspace_id.split('/')[-1]
        print_info(f"\n--- Querying Workspace: {ws_short_id} ---")
        for nsg_id in nsg_list:
            nsg_name = nsg_id.split('/')[-1]
            print_info(f"--- Processing NSG: {nsg_name} ---")
            # Initialize result status for this NSG
            analysis_summary["query_results"][nsg_id] = {"status": "pending", "total_records": 0, "batches_failed": 0}


            # Determine if batching is needed
            batch_intervals = []
            if query_batch_hours and query_batch_hours > 0 and time_range_hours > query_batch_hours:
                print_info(f"Batching enabled: Querying in {query_batch_hours}-hour intervals.")
                current_start_time = overall_start_time
                while current_start_time < overall_end_time:
                    current_end_time = min(current_start_time + timedelta(hours=query_batch_hours), overall_end_time)
                    # Ensure start time is strictly less than end time
                    if current_start_time < current_end_time:
                         batch_intervals.append((current_start_time, current_end_time))
                    current_start_time = current_end_time
            else:
                # No batching, use the overall time range
                batch_intervals.append((overall_start_time, overall_end_time))
                if query_batch_hours:
                     print_info(f"Batching interval ({query_batch_hours}h) >= total time range ({time_range_hours}h). Executing as single query.")


            print_info(f"Total query intervals for NSG '{nsg_name}': {len(batch_intervals)}")

            # Execute query for each interval (batch or single)
            nsg_total_records = 0
            nsg_batches_failed = 0
            for i, (start_dt, end_dt) in enumerate(batch_intervals):
                interval_label = f"Interval {i+1}/{len(batch_intervals)}" if len(batch_intervals) > 1 else "Full Range"
                start_str = start_dt.strftime('%Y-%m-%d %H:%M:%S UTC')
                end_str = end_dt.strftime('%Y-%m-%d %H:%M:%S UTC')
                print_info(f"Executing query for {interval_label}: {start_str} to {end_str}")

                kql_query = generate_kql_query(
                    target_ip=target_ip,
                    nsg_id=nsg_id if filter_by_nsg else None,
                    start_time_dt=start_dt,
                    end_time_dt=end_dt
                )

                # Execute the query for this batch/interval
                query_results = execute_kql_query(workspace_id, kql_query, target_ip, nsg_id, timeout_seconds)

                # Process and store results/errors for this batch
                if query_results and isinstance(query_results.get('tables'), list) and len(query_results['tables']) > 0:
                    table = query_results['tables'][0]
                    record_count = len(table.get('rows', []))
                    nsg_total_records += record_count
                    print_success(f"Batch {interval_label} for NSG '{nsg_name}' returned {record_count} records.")
                    # Convert successful results to DataFrame for later merging
                    if record_count > 0:
                        try:
                            columns = [col['name'] for col in table['columns']]
                            df = pd.DataFrame(table['rows'], columns=columns)
                            # Add batch info for potential debugging/analysis
                            df['query_batch_start'] = start_dt
                            df['query_batch_end'] = end_dt
                            all_results_df.append(df)
                        except Exception as e:
                             print_error(f"Error converting results to DataFrame for NSG {nsg_name} ({interval_label}): {e}")
                             analysis_summary["errors"].append(f"DataFrame conversion failed for NSG {nsg_name} ({interval_label}): {e}")
                             # Consider this batch as failed for status reporting
                             nsg_batches_failed += 1
                             query_execution_errors += 1


                elif query_results is not None: # Query ran but returned no data or unexpected structure
                     print_info(f"Batch {interval_label} for NSG '{nsg_name}' returned no data.")
                     # Still considered a successful execution for this batch
                else: # execute_kql_query returned None (error for this batch)
                     query_execution_errors += 1
                     nsg_batches_failed += 1
                     error_message = f"Query execution failed for NSG '{nsg_name}' ({interval_label}). See logs."
                     analysis_summary["errors"].append(f"KQL query failed for NSG {nsg_name} ({interval_label}) in workspace {ws_short_id}")
                     print_error(error_message) # Also print error to console

            # Update final status for this NSG based on batch results
            if nsg_batches_failed == len(batch_intervals): # All batches failed
                 analysis_summary["query_results"][nsg_id]["status"] = "error"
                 analysis_summary["query_results"][nsg_id]["last_error"] = "All query batches failed."
            elif nsg_batches_failed > 0: # Some batches failed
                 analysis_summary["query_results"][nsg_id]["status"] = "partial_success"
                 analysis_summary["query_results"][nsg_id]["last_error"] = f"{nsg_batches_failed} query batch(es) failed."
            else: # All batches succeeded (even if some returned no data)
                 analysis_summary["query_results"][nsg_id]["status"] = "success"
            analysis_summary["query_results"][nsg_id]["total_records"] = nsg_total_records
            analysis_summary["query_results"][nsg_id]["batches_failed"] = nsg_batches_failed


    # Phase 5: Consolidate and Save All Results to a Single Excel File
    print_info("\n===== Phase 5: Consolidating Results =====")
    if all_results_df:
        try:
            print_info(f"Consolidating results from {len(all_results_df)} successful batches/queries...")
            consolidated_df = pd.concat(all_results_df, ignore_index=True)
            # Optional: Drop duplicates if the same flow might be logged under multiple NSGs queried
            # consolidated_df.drop_duplicates(inplace=True)
            print_success(f"Total consolidated records: {len(consolidated_df)}")

            # Save consolidated results
            consolidated_excel_path = os.path.join("output", f"consolidated_results_{target_ip.replace('.', '_')}_{datetime.now().strftime('%Y%m%d%H%M%S')}.xlsx")
            try:
                 import openpyxl # Ensure engine is available
                 consolidated_df.to_excel(consolidated_excel_path, index=False, engine='openpyxl')
                 print_success(f"Consolidated results saved to: {consolidated_excel_path}")
                 analysis_summary["consolidated_results_file"] = consolidated_excel_path
            except ImportError:
                 # Logger might not be available if setup failed earlier, use print_error
                 print_error("Module 'openpyxl' not found. Cannot save consolidated Excel. Run: pip install openpyxl")
                 analysis_summary["errors"].append("Consolidated Excel saving failed: openpyxl not found.")
            except Exception as e:
                 # Logger might not be available if setup failed earlier, use print_error
                 print_error(f"Error saving consolidated Excel file: {e}")
                 analysis_summary["errors"].append(f"Consolidated Excel saving failed: {e}")

        except Exception as e:
            print_error(f"Error consolidating DataFrames: {e}")
            analysis_summary["errors"].append(f"Result consolidation failed: {e}")
    elif execute_query and query_execution_errors == 0:
         print_info("All queries executed successfully, but no records were found to consolidate.")
    elif execute_query:
         print_warning("No successful query results with data found to consolidate, possibly due to query errors.")


    print_info("\n===== Analysis Complete =====")
    # Save final summary
    save_json(analysis_summary, os.path.join("output", f"analysis_summary_{target_ip.replace('.', '_')}.json"))

    return analysis_summary


def main():
    parser = argparse.ArgumentParser(description="Find Azure NSGs associated with an IP and query NSG flow logs.")
    parser.add_argument("ip_address", help="The target IP address to analyze.")
    parser.add_argument("--time-range", type=int, default=24, help="Time range in hours for KQL query (default: 24)")
    parser.add_argument("--filter-nsg", action=argparse.BooleanOptionalAction, default=True, help="Filter KQL query by specific NSG (default: True)")
    parser.add_argument("--execute", action=argparse.BooleanOptionalAction, default=True, help="Execute KQL queries (default: True). Use --no-execute to only find NSGs/configs and generate sample queries.")
    parser.add_argument("--timeout", type=int, default=180, help="Timeout in seconds for each KQL query execution via Azure CLI (default: 180)")
    parser.add_argument("--batch-hours", type=int, default=None, help="Optional: Split query into batches of this many hours to avoid size limits (e.g., 1, 6, 24)")

    args = parser.parse_args()

    # --- Logger Setup for main function ---
    output_dir = "output" # Define output dir for logger path
    log_dir = os.path.join(output_dir, "logs")
    # Use a generic name for the main log, or one based on the script itself
    main_log_file_name = f"script_execution_{datetime.now().strftime('%Y%m%d')}.log"
    main_log_file_path = os.path.join(log_dir, main_log_file_name)
    # Initialize logger here so it's available throughout main
    logger = setup_logger(main_log_file_path)
    logger.info(f"--- Script execution started for IP: {args.ip_address} ---")


    # Validate IP address format
    try:
        ipaddress.ip_address(args.ip_address)
    except ValueError:
        logger.error(f"Invalid IP address format provided: {args.ip_address}")
        print_error(f"Invalid IP address format: {args.ip_address}")
        sys.exit(1)

    # Ensure user is logged into Azure CLI
    try:
        logger.info("Checking Azure CLI login status...")
        print_info("Checking Azure CLI login status...")
        # Use a less verbose command for checking login status if possible, but `az account show` is standard
        subprocess.run("az account show", shell=True, check=True, capture_output=True, text=True, encoding='utf-8')
        logger.info("Azure CLI login verified.")
        print_success("Azure CLI login verified.")
    except subprocess.CalledProcessError:
        logger.error("Azure CLI login required. Please run 'az login'.")
        print_error("Azure CLI login required. Please run 'az login' and try again.")
        sys.exit(1)
    except FileNotFoundError:
         logger.error("Azure CLI ('az') command not found.")
         print_error("Azure CLI ('az') command not found. Please ensure it's installed and in your PATH.")
         sys.exit(1)


    # Run the analysis
    analysis_results = analyze_traffic(
        target_ip=args.ip_address,
        time_range_hours=args.time_range,
        filter_by_nsg=args.filter_nsg,
        execute_query=args.execute,
        timeout_seconds=args.timeout,
        query_batch_hours=args.batch_hours
    )

    # Print summary information from results
    print("\n--- Analysis Summary ---")
    logger.info("--- Analysis Summary ---")
    print(f"Target IP: {analysis_results['target_ip']}")
    logger.info(f"Target IP: {analysis_results['target_ip']}")
    print(f"NSGs Found: {len(analysis_results['nsgs_found'])}")
    logger.info(f"NSGs Found: {len(analysis_results['nsgs_found'])}")
    print(f"Workspaces Queried: {len(analysis_results['workspaces_queried'])}")
    logger.info(f"Workspaces Queried: {len(analysis_results['workspaces_queried'])}")

    # Summarize query results status
    success_count = sum(1 for res in analysis_results['query_results'].values() if res['status'] == 'success')
    partial_count = sum(1 for res in analysis_results['query_results'].values() if res['status'] == 'partial_success')
    error_count = sum(1 for res in analysis_results['query_results'].values() if res['status'] == 'error')
    print(f"Query Status (by NSG): Success={success_count}, Partial Success={partial_count}, Error={error_count}")
    logger.info(f"Query Status (by NSG): Success={success_count}, Partial Success={partial_count}, Error={error_count}")


    if analysis_results.get('consolidated_results_file'):
        print(f"Consolidated Excel Report: {analysis_results['consolidated_results_file']}")
        logger.info(f"Consolidated Excel Report: {analysis_results['consolidated_results_file']}")
    # Check if queries were executed, no errors occurred, and no records found
    elif analysis_results['execute_query'] and not analysis_results['errors'] and not any(res.get('total_records', 0) > 0 for res in analysis_results['query_results'].values() if res.get('status') != 'error'):
         no_records_msg = "Analysis completed, but no flow log records were found for the specified IP and time range across all queried NSGs."
         print(no_records_msg)
         logger.info(no_records_msg)


    if analysis_results['errors']:
        print_warning("\nErrors encountered during analysis:")
        # Print unique errors
        unique_errors = sorted(list(set(analysis_results['errors'])))
        for error in unique_errors:
            print(f"- {error}")
            logger.warning(f"Analysis Error: {error}") # Log errors as warnings in main log

    logger.info(f"--- Script execution finished for IP: {args.ip_address} ---")


if __name__ == "__main__":
    # Check for required dependencies first
    try:
        import pandas
        import openpyxl # Check for excel engine too
    except ImportError as e:
        # Use basic print here as logger might not be set up yet
        print(f"{Colors.RED}Missing required Python package: {e.name}. Please install it.{Colors.RESET}")
        print(f"{Colors.RED}You can likely install required packages using: pip install pandas openpyxl{Colors.RESET}")
        sys.exit(1)

    main()
