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
import pandas as pd # Add pandas import

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

    # Step 3 (Searching all subnets for IP range containment) has been removed for simplification
    # as Step 1 and Step 2 usually cover the necessary NSG discovery.
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
    """Configure logger"""
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

    # --- Logging Setup ---
    output_dir = "output"
    log_dir = os.path.join(output_dir, "logs")
    # Log file name based on IP and Date
    log_file_name = f"query_log_{target_ip.replace('.', '_')}_{datetime.now().strftime('%Y%m%d')}.log"
    log_file_path = os.path.join(log_dir, log_file_name)
    # Using file path is sufficient for logger name uniqueness
    logger = setup_logger(log_file_path) # Setup ensures directory exists

    nsg_name = nsg_id.split('/')[-1] # For logging clarity
    logger.info(f"--- Starting KQL Query Execution ---")
    logger.info(f"Target IP: {target_ip}")
    logger.info(f"NSG Name: {nsg_name}")
    logger.info(f"Workspace ID: {workspace_id}")
    logger.info(f"Timeout Seconds: {timeout_seconds}")

    # --- KQL Query Preparation ---
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
            # Clean the stdout string before parsing
            cleaned_stdout = stdout.strip()
            if cleaned_stdout.startswith('\ufeff'):
                logger.info("Removing BOM from stdout before JSON parsing.")
                cleaned_stdout = cleaned_stdout[1:]

            parsed_json = json.loads(cleaned_stdout) # Parse the cleaned string

            # --- Handle potential output format variations ---
            results = None # Initialize results variable
            if isinstance(parsed_json, dict) and 'tables' in parsed_json:
                # Case 1: Standard format {"tables": [...]}
                results = parsed_json
                logger.info(f"Query for NSG '{nsg_name}' returned standard JSON object format.")
            elif isinstance(parsed_json, list):
                # Case 2: Observed format [...] (array of row objects)
                logger.warning(f"Query for NSG '{nsg_name}' returned a JSON array directly. Attempting to wrap into standard format.")
                columns = []
                rows_as_lists = []
                if len(parsed_json) > 0 and isinstance(parsed_json[0], dict):
                    # Infer columns from the keys of the first row object
                    columns = [{"name": k, "type": "string"} for k in parsed_json[0].keys()] # Assume string type for simplicity
                    col_names = [c['name'] for c in columns]
                    # Convert list of dictionaries to list of lists based on inferred column order
                    for row_dict in parsed_json:
                         rows_as_lists.append([row_dict.get(col_name) for col_name in col_names])
                    logger.info(f"Inferred {len(columns)} columns from JSON array.")
                else:
                     logger.warning(f"JSON array for NSG '{nsg_name}' was empty or did not contain objects; cannot infer structure.")

                # Reconstruct the standard dictionary format
                results = {
                    "tables": [
                        {
                            "name": "PrimaryResult", # Standard name used by Log Analytics
                            "columns": columns,
                            "rows": rows_as_lists
                        }
                    ]
                }
            else:
                # Case 3: Neither format is recognized
                 logger.warning(f"Query for NSG '{nsg_name}' returned JSON, but with unexpected structure. Type: {type(parsed_json)}. Raw output saved.")
                 print_warning(f"Query for NSG '{nsg_name}' returned unexpected JSON structure. Raw output saved.")
                 raw_output_path = os.path.join(output_dir, f"query_results_{target_ip}_{nsg_name}_{timestamp}_raw.txt")
                 try:
                     with open(raw_output_path, 'w', encoding='utf-8') as rf: rf.write(stdout) # Save original stdout
                     logger.info(f"Raw output saved to {raw_output_path}")
                 except IOError as e:
                     logger.error(f"Failed to save raw output to {raw_output_path}: {e}")
                 results = {"tables": []} # Return empty structure to avoid downstream errors

        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse JSON response for NSG '{nsg_name}': {e}")
            logger.error(f"Raw Stdout (first 1000 chars):\n{stdout[:1000]}")
            print_error(f"Failed to parse JSON response for NSG '{nsg_name}'. See log: {log_file_path}")
            # Save raw output for debugging
            raw_output_path = os.path.join(output_dir, f"query_results_{target_ip}_{nsg_name}_{timestamp}_error.txt")
            try:
                with open(raw_output_path, 'w', encoding='utf-8') as rf: rf.write(stdout)
                logger.info(f"Raw output saved to {raw_output_path}")
            except IOError as io_e:
                logger.error(f"Failed to save raw error output to {raw_output_path}: {io_e}")
            return None # Return None on JSON parsing error

    except subprocess.TimeoutExpired:
        logger.error(f"KQL query command timed out after {cli_timeout} seconds for NSG '{nsg_name}'.")
        print_error(f"KQL query command timed out for NSG '{nsg_name}'. Try increasing the timeout or reducing the time range.")
        if process:
            process.kill() # Ensure the process is terminated
            stdout, stderr = process.communicate() # Capture any final output
            logger.warning(f"Process killed due to timeout. Final stdout: {stdout[:500]}..., stderr: {stderr[:500]}...")
        return None # Return None on timeout
    except Exception as e:
        logger.exception(f"An unexpected error occurred during KQL query execution for NSG '{nsg_name}': {e}")
        print_error(f"An unexpected error occurred during KQL query for NSG '{nsg_name}'. See log: {log_file_path}")
        return None # Return None on other exceptions
    finally:
        # Clean up the temporary query file
        try:
            if os.path.exists(temp_query_file):
                os.remove(temp_query_file)
                logger.info(f"Temporary query file removed: {temp_query_file}")
        except OSError as e:
            logger.warning(f"Failed to remove temporary query file {temp_query_file}: {e}")

    # --- Save Results to Excel ---
    if results and results.get("tables"):
        try:
            # Extract data for DataFrame
            primary_table = results['tables'][0]
            columns = [col['name'] for col in primary_table['columns']]
            data = primary_table['rows']

            if data: # Only save if there is data
                df = pd.DataFrame(data, columns=columns)
                excel_file_name = f"query_results_{target_ip}_{nsg_name}_{timestamp}.xlsx"
                excel_file_path = os.path.join(output_dir, excel_file_name)

                # Ensure output directory exists (should already, but double-check)
                os.makedirs(output_dir, exist_ok=True)

                df.to_excel(excel_file_path, index=False, engine='openpyxl') # Specify engine
                logger.info(f"Query results saved to Excel: {excel_file_path}")
                print_success(f"Query results for NSG '{nsg_name}' saved to: {excel_file_path}")
            else:
                logger.info(f"No rows returned in the query result for NSG '{nsg_name}'. Excel file not created.")
                print_info(f"No data returned from query for NSG '{nsg_name}'.")

        except ImportError:
            logger.warning("Pandas or openpyxl not installed. Cannot save results to Excel. Please install with: pip install pandas openpyxl")
            print_warning("Pandas or openpyxl not installed. Skipping Excel export.")
        except KeyError as e:
            logger.error(f"Unexpected structure in KQL result JSON for NSG '{nsg_name}', missing key: {e}. Cannot process for Excel.")
            print_error(f"Unexpected KQL result structure for NSG '{nsg_name}'. Cannot save to Excel.")
        except Exception as e:
            logger.exception(f"Failed to save results to Excel for NSG '{nsg_name}': {e}")
            print_error(f"Failed to save results to Excel for NSG '{nsg_name}'. See log: {log_file_path}")

    logger.info(f"--- Finished KQL Query Execution for NSG {nsg_name} ---")
    return results # Return the parsed JSON results (or the wrapped structure)


def generate_simple_kql_query(target_ip: str, time_range_hours: int = 24) -> str:
    """Generates a basic KQL query for NSG flow logs"""
    # Calculate time range
    end_time = datetime.now(timezone.utc)
    start_time = end_time - timedelta(hours=time_range_hours)
    start_time_str = start_time.strftime('%Y-%m-%dT%H:%M:%SZ')
    end_time_str = end_time.strftime('%Y-%m-%dT%H:%M:%SZ')

    # Basic query structure - assumes AzureNetworkAnalytics_CL table
    # Adjust table name if necessary (e.g., NetworkMonitoring)
    kql = f"""
AzureNetworkAnalytics_CL
| where TimeGenerated between (datetime({start_time_str}) .. datetime({end_time_str}))
| where FlowType_s == "AzureNetwork" // Focus on NSG flows
| where SubType_s == "FlowLog"
| where PublicIPs_s contains "{target_ip}" or SrcIP_s == "{target_ip}" or DestIP_s == "{target_ip}"
| project TimeGenerated, FlowStartTime_t, FlowEndTime_t, NSGName=NSGName_s, NSGRuleName_s, SrcIP_s, DestIP_s, SrcPort_d, DestPort_d, Protocol_s=L4Protocol_s, FlowDirection_s, Allowed=isnotempty(NSGRuleName_s) and AllowedOrDenied_s == 'Allowed', PublicIPs_s, VMIP_s, SubscriptionId=SubscriptionId_g, ResourceGroup=ResourceGroup_s
| order by TimeGenerated desc
| limit 1000 // Add a limit to prevent excessively large results initially
"""
    return kql

def generate_kql_query(target_ip: str,
                       time_range_hours: int = 24,
                       include_public_ips: bool = True,
                       include_private_ips: bool = True,
                       flow_type: str = "AzureNetwork", # or "AWSNetwork", etc.
                       sub_type: str = "FlowLog",
                       limit: int = 1000,
                       custom_table_name: Optional[str] = None) -> str:
    """
    Generates a more flexible KQL query for network flow logs.

    Args:
        target_ip: The IP address to search for.
        time_range_hours: The lookback period in hours.
        include_public_ips: Whether to search in the PublicIPs_s field.
        include_private_ips: Whether to search in SrcIP_s and DestIP_s fields.
        flow_type: The FlowType_s value to filter on.
        sub_type: The SubType_s value to filter on.
        limit: The maximum number of results to return.
        custom_table_name: Override the default table name (AzureNetworkAnalytics_CL).

    Returns:
        The generated KQL query string.
    """
    if not include_public_ips and not include_private_ips:
        raise ValueError("At least one of include_public_ips or include_private_ips must be True")

    end_time = datetime.now(timezone.utc)
    start_time = end_time - timedelta(hours=time_range_hours)
    start_time_str = start_time.strftime('%Y-%m-%dT%H:%M:%SZ')
    end_time_str = end_time.strftime('%Y-%m-%dT%H:%M:%SZ')

    table_name = custom_table_name if custom_table_name else "AzureNetworkAnalytics_CL"

    ip_conditions = []
    if include_public_ips:
        ip_conditions.append(f'PublicIPs_s contains "{target_ip}"')
    if include_private_ips:
        ip_conditions.append(f'SrcIP_s == "{target_ip}"')
        ip_conditions.append(f'DestIP_s == "{target_ip}"')

    ip_filter = " or ".join(ip_conditions)

    kql = f"""
{table_name}
| where TimeGenerated between (datetime({start_time_str}) .. datetime({end_time_str}))
| where FlowType_s == "{flow_type}"
| where SubType_s == "{sub_type}"
| where {ip_filter}
| project TimeGenerated, FlowStartTime=FlowStartTime_t, FlowEndTime=FlowEndTime_t, NSGName=NSGName_s, NSGRule=NSGRuleName_s, SrcIP=SrcIP_s, DestIP=DestIP_s, SrcPort=SrcPort_d, DestPort=DestPort_d, Protocol=L4Protocol_s, Direction=FlowDirection_s, Action=AllowedOrDenied_s, PublicIPs=PublicIPs_s, VMIP=VMIP_s, SubscriptionId=SubscriptionId_g, ResourceGroup=ResourceGroup_s, VMName=VMName_s, NIC=NicName_s, Subnet=SubnetName_s, VNet=VnetName_s
| order by TimeGenerated desc
| limit {limit}
"""
    return kql.strip()


def analyze_traffic(target_ip: str, time_range_hours: int = 24, logger: Optional[logging.Logger] = None) -> Dict[str, Any]:
    """
    Main analysis function: Finds NSGs, gets configs, queries logs.

    Args:
        target_ip: The IP address to analyze.
        time_range_hours: The lookback period for KQL queries in hours.
        logger: Optional logger instance.

    Returns:
        A dictionary containing analysis results (NSG IDs, configs, workspace map, query status).
    """
    if not logger:
        # Setup default logger if none provided
        output_dir = "output"
        log_dir = os.path.join(output_dir, "logs")
        log_file_name = f"analysis_log_{target_ip.replace('.', '_')}_{datetime.now().strftime('%Y%m%d')}.log"
        log_file_path = os.path.join(log_dir, log_file_name)
        logger = setup_logger(log_file_path)
        logger.info("Default logger initialized for analyze_traffic.")

    logger.info(f"--- Starting Traffic Analysis for IP: {target_ip} ---")
    logger.info(f"Time Range (Hours): {time_range_hours}")

    analysis_results = {
        "target_ip": target_ip,
        "time_range_hours": time_range_hours,
        "found_nsg_ids": [],
        "flow_logs_config": {},
        "workspace_ids_map": {},
        "kql_query_status": {}, # Tracks success/failure per NSG/workspace
        "summary": [] # List of summary messages
    }

    # Validate IP address format
    try:
        ipaddress.ip_address(target_ip)
        logger.info(f"Target IP {target_ip} format is valid.")
    except ValueError:
        error_msg = f"Invalid IP address format: {target_ip}"
        print_error(error_msg)
        logger.error(error_msg)
        analysis_results["summary"].append(error_msg)
        return analysis_results # Exit early if IP is invalid

    # Step 1 & 2: Find NSGs associated with the IP
    try:
        nsg_ids = find_nsgs_by_ip(target_ip)
        analysis_results["found_nsg_ids"] = nsg_ids
        if not nsg_ids:
            warning_msg = f"No NSGs found associated with IP {target_ip}. Analysis cannot proceed further."
            print_warning(warning_msg)
            logger.warning(warning_msg)
            analysis_results["summary"].append(warning_msg)
            return analysis_results
        else:
            success_msg = f"Successfully found {len(nsg_ids)} potential NSG(s) related to IP {target_ip}."
            logger.info(success_msg)
            analysis_results["summary"].append(success_msg)

    except Exception as e:
        error_msg = f"Error during NSG discovery for IP {target_ip}: {e}"
        print_error(error_msg)
        logger.exception(error_msg) # Log full traceback
        analysis_results["summary"].append(error_msg)
        return analysis_results # Stop if NSG discovery fails

    # Step 3 & 4: Get Flow Logs config and Workspace IDs
    try:
        flow_logs_config = get_nsg_flow_logs_config(nsg_ids, target_ip)
        analysis_results["flow_logs_config"] = flow_logs_config

        if not flow_logs_config:
             warning_msg = f"No flow log configurations found for the identified NSGs. Cannot query logs."
             print_warning(warning_msg)
             logger.warning(warning_msg)
             analysis_results["summary"].append(warning_msg)
             return analysis_results
        else:
            logger.info(f"Retrieved flow log configurations for {len(flow_logs_config)} NSG(s).")

        workspace_ids_map = get_log_analytics_workspaces(flow_logs_config, target_ip)
        analysis_results["workspace_ids_map"] = workspace_ids_map

        if not workspace_ids_map:
            warning_msg = f"No Log Analytics Workspaces identified from flow log configurations. Cannot query logs."
            print_warning(warning_msg)
            logger.warning(warning_msg)
            analysis_results["summary"].append(warning_msg)
            return analysis_results
        else:
             success_msg = f"Identified {len(workspace_ids_map)} Log Analytics Workspace(s) to query."
             logger.info(success_msg)
             analysis_results["summary"].append(success_msg)

    except Exception as e:
        error_msg = f"Error getting flow log/workspace info for IP {target_ip}: {e}"
        print_error(error_msg)
        logger.exception(error_msg)
        analysis_results["summary"].append(error_msg)
        return analysis_results # Stop if config retrieval fails

    # Step 5: Execute KQL Queries for each workspace
    print_info(f"\nStep 6: Executing KQL queries for IP {target_ip} across identified workspaces...")
    logger.info("--- Starting KQL Query Phase ---")

    queried_workspaces = set() # Keep track of workspaces already queried to avoid duplicates

    for nsg_id, workspace_id in workspace_ids_map.items():
        nsg_name = nsg_id.split('/')[-1] # For logging/reporting
        query_key = f"{nsg_id} -> {workspace_id}" # Unique key for status

        # Skip if workspace ID is invalid or already queried for this analysis run
        if not workspace_id or workspace_id in queried_workspaces:
            if not workspace_id:
                 logger.warning(f"Skipping KQL query for NSG '{nsg_name}' due to missing workspace ID.")
            else:
                 logger.info(f"Workspace {workspace_id} already queried for NSG '{nsg_name}' in this run. Skipping duplicate query.")
            analysis_results["kql_query_status"][query_key] = "Skipped (Missing ID or Duplicate)"
            continue

        logger.info(f"Preparing KQL query for NSG '{nsg_name}' against Workspace ID: {workspace_id}")

        # Generate the KQL query
        # You can choose between generate_simple_kql_query or the more flexible generate_kql_query
        # kql_query = generate_simple_kql_query(target_ip, time_range_hours)
        kql_query = generate_kql_query(
            target_ip=target_ip,
            time_range_hours=time_range_hours,
            limit=2000 # Increase limit slightly if needed
        )
        logger.debug(f"Generated KQL for NSG '{nsg_name}':\n{kql_query}")

        # Execute the query
        try:
            query_result = execute_kql_query(workspace_id, kql_query, target_ip, nsg_id) # Pass logger

            if query_result is not None:
                # Check if data was actually returned
                data_returned = False
                if query_result.get("tables") and len(query_result["tables"]) > 0:
                     if query_result["tables"][0].get("rows") and len(query_result["tables"][0]["rows"]) > 0:
                         data_returned = True

                if data_returned:
                    status_msg = f"Success (Data Found)"
                    logger.info(f"KQL query successful for NSG '{nsg_name}', data found.")
                else:
                    status_msg = f"Success (No Data)"
                    logger.info(f"KQL query successful for NSG '{nsg_name}', but no matching data returned.")

                analysis_results["kql_query_status"][query_key] = status_msg
                queried_workspaces.add(workspace_id) # Mark workspace as queried

            else:
                # execute_kql_query handles logging/printing errors internally
                analysis_results["kql_query_status"][query_key] = "Failed"
                logger.error(f"KQL query failed for NSG '{nsg_name}' against workspace {workspace_id}.")
                # Optionally add a summary message about the failure
                analysis_results["summary"].append(f"KQL query failed for NSG '{nsg_name}'. Check logs.")


        except Exception as e:
            error_msg = f"Unexpected error during KQL execution for NSG '{nsg_name}': {e}"
            print_error(error_msg)
            logger.exception(error_msg)
            analysis_results["kql_query_status"][query_key] = f"Error: {e}"
            analysis_results["summary"].append(error_msg)

    logger.info("--- Finished KQL Query Phase ---")

    # Final Summary
    print_info("\n--- Analysis Summary ---")
    print(f"Target IP: {target_ip}")
    print(f"Time Range (Hours): {time_range_hours}")
    print(f"Found NSGs: {len(analysis_results['found_nsg_ids'])}")
    print(f"Flow Log Configs Found: {len(analysis_results['flow_logs_config'])}")
    print(f"Workspaces Queried: {len(queried_workspaces)}")
    print("KQL Query Status:")
    for key, status in analysis_results['kql_query_status'].items():
        nsg_part = key.split(' -> ')[0].split('/')[-1]
        ws_part = key.split(' -> ')[1].split('/')[-1] # Show short workspace ID
        print(f"  - NSG: {nsg_part}, Workspace: {ws_part}: {status}")

    # Save the overall analysis results summary
    summary_file = os.path.join("output", f"analysis_summary_{target_ip}.json")
    save_json(analysis_results, summary_file)
    logger.info(f"Analysis summary saved to {summary_file}")

    logger.info(f"--- Finished Traffic Analysis for IP: {target_ip} ---")
    return analysis_results

def main():
    parser = argparse.ArgumentParser(description="Find Azure NSGs associated with an IP and query flow logs.")
    parser.add_argument("ip_address", help="The target IP address to analyze.")
    parser.add_argument("-t", "--time-range", type=int, default=24,
                        help="Time range in hours to query flow logs (default: 24).")
    parser.add_argument("--timeout", type=int, default=300,
                        help="Timeout in seconds for KQL queries (default: 300).") # Added timeout argument

    # Add arguments for KQL query generation flexibility (optional)
    parser.add_argument("--kql-no-public", action="store_false", dest="include_public",
                        help="Do not search in PublicIPs_s field in KQL.")
    parser.add_argument("--kql-no-private", action="store_false", dest="include_private",
                        help="Do not search in SrcIP_s/DestIP_s fields in KQL.")
    parser.add_argument("--kql-limit", type=int, default=2000,
                        help="Limit the number of results from KQL query (default: 2000).")
    parser.add_argument("--kql-table", type=str, default=None,
                        help="Specify a custom table name for KQL query (default: AzureNetworkAnalytics_CL).")


    args = parser.parse_args()

    # --- Setup Central Logger ---
    output_dir = "output"
    log_dir = os.path.join(output_dir, "logs")
    # Main log file for the overall script execution
    main_log_file_name = f"main_script_log_{args.ip_address.replace('.', '_')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
    main_log_file_path = os.path.join(log_dir, main_log_file_name)
    # Use a distinct name for the main logger
    main_logger = setup_logger(main_log_file_path)
    main_logger.info(f"--- Script Started: {sys.argv[0]} ---")
    main_logger.info(f"Arguments: IP={args.ip_address}, TimeRange={args.time_range}, Timeout={args.timeout}")
    main_logger.info(f"KQL Options: Public={args.include_public}, Private={args.include_private}, Limit={args.kql_limit}, Table={args.kql_table}")


    # --- Execute Analysis ---
    try:
        # Pass the main logger to the analysis function
        analysis_summary = analyze_traffic(args.ip_address, args.time_range, logger=main_logger)

        # Optional: Print a final confirmation based on summary
        if analysis_summary and analysis_summary.get("kql_query_status"):
             print_success("\nAnalysis complete. Check the 'output' directory for detailed JSON/Excel files and logs.")
             main_logger.info("Analysis completed successfully.")
        else:
             print_warning("\nAnalysis finished, but some steps may have encountered issues or returned no data. Check logs and output files.")
             main_logger.warning("Analysis finished with potential issues or no data.")

    except Exception as e:
        error_msg = f"An unhandled error occurred in main execution: {e}"
        print_error(error_msg)
        main_logger.exception(error_msg) # Log the full traceback for unhandled errors
        sys.exit(1) # Exit with error code
    finally:
        main_logger.info(f"--- Script Finished: {sys.argv[0]} ---")


if __name__ == "__main__":
    main()