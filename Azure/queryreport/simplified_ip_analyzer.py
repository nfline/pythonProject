import os
import sys
import json
import argparse
import subprocess
import ipaddress
import logging
from datetime import datetime, timedelta, timezone
from typing import List, Dict, Any, Optional, Tuple
import pandas as pd

# --- Configuration ---
OUTPUT_DIR = "output"
LOG_DIR = os.path.join(OUTPUT_DIR, "logs")
RESULTS_DIR = os.path.join(OUTPUT_DIR, "query_results")
DEFAULT_TIMEOUT = 300 # Increased default timeout slightly

# --- Basic Logging Setup ---
os.makedirs(LOG_DIR, exist_ok=True)
os.makedirs(RESULTS_DIR, exist_ok=True)
log_file_path = os.path.join(LOG_DIR, f"simplified_analyzer_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log")
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(log_file_path, encoding='utf-8'),
        logging.StreamHandler(sys.stdout) # Also print info/errors to console
    ]
)
logger = logging.getLogger(__name__)

# --- Helper Functions ---

def run_command(cmd: str) -> Optional[Dict]:
    """Run command and return JSON result, with basic logging."""
    logger.info(f"Executing command: {cmd[:150]}...") # Log truncated command
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, check=False, encoding='utf-8', timeout=DEFAULT_TIMEOUT + 60)

        if result.returncode != 0:
            logger.error(f"Command failed. Return Code: {result.returncode}")
            logger.error(f"Stderr: {result.stderr.strip()}")
            print(f"ERROR: Command execution failed. Check log: {log_file_path}", file=sys.stderr)
            return None

        if not result.stdout.strip():
            logger.warning("Command executed successfully but returned no output.")
            return None # Treat no output as None for simplicity downstream

        # Attempt to parse JSON, handle BOM if present
        cleaned_stdout = result.stdout.strip()
        if cleaned_stdout.startswith('\ufeff'):
            cleaned_stdout = cleaned_stdout[1:]

        try:
            return json.loads(cleaned_stdout)
        except json.JSONDecodeError as e:
            logger.error(f"Failed to decode JSON response: {e}")
            logger.debug(f"Non-JSON output received: {cleaned_stdout[:500]}...")
            print(f"ERROR: Command output was not valid JSON. Check log: {log_file_path}", file=sys.stderr)
            return None # Treat non-JSON as failure

    except subprocess.TimeoutExpired:
        logger.error(f"Command timed out after {DEFAULT_TIMEOUT + 60} seconds.")
        print(f"ERROR: Command timed out. Check log: {log_file_path}", file=sys.stderr)
        return None
    except Exception as e:
        logger.exception(f"Error running command: {e}") # Log full exception traceback
        print(f"ERROR: An unexpected error occurred running command. Check log: {log_file_path}", file=sys.stderr)
        return None

def ip_in_subnet(ip_address: str, subnet_prefix: str) -> bool:
    """Check if IP is within subnet range using ipaddress module."""
    try:
        network = ipaddress.ip_network(subnet_prefix, strict=False)
        ip = ipaddress.ip_address(ip_address)
        return ip in network
    except ValueError as e:
        logger.warning(f"Error parsing IP '{ip_address}' or subnet '{subnet_prefix}': {e}")
        return False

def find_related_nsgs_and_workspaces(target_ip: str) -> Dict[str, List[str]]:
    """
    Finds NSGs related to the IP (via NICs and Subnets) and maps them to their Log Analytics Workspace IDs.
    Returns a dictionary mapping Workspace ID to a list of associated NSG IDs.
    """
    logger.info(f"Starting search for NSGs and Workspaces related to IP: {target_ip}")
    nsg_ids_found = set()
    workspace_map = {} # nsg_id -> workspace_id
    workspaces_to_query = {} # workspace_id -> [nsg_ids]

    # 1. Find NICs using the IP via Azure Resource Graph
    logger.info("Step 1: Finding network interfaces via IP...")
    nic_cmd = f"az graph query -q \"Resources | where type =~ 'microsoft.network/networkinterfaces' | where properties.ipConfigurations contains '{target_ip}' | project id, name, nsgId = tostring(properties.networkSecurityGroup.id), subnetId = tostring(properties.ipConfigurations[0].properties.subnet.id)\" --query \"data\" -o json"
    nics = run_command(nic_cmd)
    nic_subnet_ids = set()

    if nics and isinstance(nics, list):
        logger.info(f"Found {len(nics)} NICs potentially associated with {target_ip}.")
        for nic in nics:
            nsg_id = nic.get('nsgId')
            if nsg_id:
                nsg_ids_found.add(nsg_id)
                logger.debug(f"Found NSG from NIC '{nic.get('name')}': {nsg_id}")
            subnet_id = nic.get('subnetId')
            if subnet_id:
                nic_subnet_ids.add(subnet_id)
    else:
        logger.warning(f"No NICs found directly associated with {target_ip} via Graph query, or query failed.")

    # 2. Find NSGs associated with the Subnets found via NICs
    if nic_subnet_ids:
        logger.info(f"Step 2: Checking {len(nic_subnet_ids)} subnets found via NICs...")
        subnet_ids_str = '","'.join(nic_subnet_ids)
        # Use Graph query to get NSGs for multiple subnets at once
        subnet_nsg_cmd = f"az graph query -q \"Resources | where type =~ 'microsoft.network/virtualnetworks/subnets' and id in ('{subnet_ids_str}') | project id, name, nsgId = tostring(properties.networkSecurityGroup.id)\" --query \"data\" -o json"
        subnet_details_list = run_command(subnet_nsg_cmd)
        if subnet_details_list and isinstance(subnet_details_list, list):
            for subnet_detail in subnet_details_list:
                nsg_id = subnet_detail.get('nsgId')
                if nsg_id:
                    nsg_ids_found.add(nsg_id)
                    logger.debug(f"Found NSG from Subnet '{subnet_detail.get('name')}': {nsg_id}")
        else:
             logger.warning(f"Could not retrieve NSG details for subnets: {nic_subnet_ids}")


    # 3. Find Subnets containing the IP range and their NSGs (Comprehensive Check)
    logger.info("Step 3: Searching all subnets for IP range containment...")
    subnets_cmd = "az graph query -q \"Resources | where type =~ 'microsoft.network/virtualnetworks/subnets' | project id, name, addressPrefix = properties.addressPrefix, addressPrefixes = properties.addressPrefixes, nsgId = tostring(properties.networkSecurityGroup.id)\" --query \"data\" -o json"
    all_subnets = run_command(subnets_cmd)

    if all_subnets and isinstance(all_subnets, list):
        logger.info(f"Checking {len(all_subnets)} total subnets for IP containment.")
        for subnet in all_subnets:
            prefixes = []
            if subnet.get('addressPrefix'):
                prefixes.append(subnet['addressPrefix'])
            if isinstance(subnet.get('addressPrefixes'), list):
                prefixes.extend(subnet['addressPrefixes'])

            for prefix in set(prefixes):
                if prefix and ip_in_subnet(target_ip, prefix):
                    logger.debug(f"IP {target_ip} is within subnet '{subnet.get('name')}' range {prefix}")
                    nsg_id = subnet.get('nsgId')
                    if nsg_id:
                        nsg_ids_found.add(nsg_id)
                        logger.debug(f"Found NSG from containing subnet '{subnet.get('name')}': {nsg_id}")
                    # Break inner loop once IP is found in one of the subnet's prefixes
                    break
    else:
        logger.warning("Unable to get the list of all subnets via Graph query, or query failed.")

    if not nsg_ids_found:
        logger.warning(f"No NSGs found related to IP {target_ip} after all checks.")
        return {}

    logger.info(f"Found {len(nsg_ids_found)} unique NSG(s) potentially related to {target_ip}: {', '.join(nsg_ids_found)}")

    # 4. Get Flow Log config and Workspace ID for each NSG
    logger.info("Step 4: Getting Flow Log configurations and Workspace IDs...")
    nsg_ids_list_str = '","'.join(nsg_ids_found)
    # Graph query to get flow log details including workspace ID for multiple NSGs
    flow_logs_cmd = f"az graph query -q \"Resources | where type =~ 'Microsoft.Network/networkWatchers/flowLogs' and properties.targetResourceId in ('{nsg_ids_list_str}') | project targetResourceId = tostring(properties.targetResourceId), workspaceId=properties.flowAnalyticsConfiguration.networkWatcherFlowAnalyticsConfiguration.workspaceId, enabled=properties.enabled\" --query \"data\" -o json"

    flow_logs_list = run_command(flow_logs_cmd)

    if flow_logs_list and isinstance(flow_logs_list, list):
        for config in flow_logs_list:
            nsg_id = config.get('targetResourceId')
            workspace_id = config.get('workspaceId')
            enabled = config.get('enabled', False)

            if not nsg_id or nsg_id not in nsg_ids_found:
                logger.warning(f"Flow log config found for unknown/unexpected NSG: {nsg_id}")
                continue

            if not enabled:
                logger.warning(f"Flow logs are disabled for NSG: {nsg_id}")
                continue # Skip disabled flow logs

            if workspace_id:
                 # Basic validation of workspace ID format (GUID or full resource ID)
                is_guid = len(workspace_id) == 36 and workspace_id.count('-') == 4
                is_full_id = '/subscriptions/' in workspace_id and '/workspaces/' in workspace_id
                if is_full_id or is_guid:
                    workspace_map[nsg_id] = workspace_id
                    logger.info(f"Found enabled Flow Log config for NSG {nsg_id} sending to Workspace: {workspace_id}")
                else:
                    logger.warning(f"NSG {nsg_id} has Flow Log config, but workspace ID format is unexpected: {workspace_id}")
            else:
                logger.warning(f"NSG {nsg_id} has enabled Flow Log config, but Workspace ID is missing. Cannot query.")
    else:
        logger.warning(f"Could not retrieve any flow log configurations for the found NSGs, or query failed.")


    if not workspace_map:
        logger.warning("No valid Log Analytics Workspaces found associated with the NSGs' flow logs.")
        return {}

    # Group NSGs by Workspace ID
    for nsg_id, ws_id in workspace_map.items():
        # Use the short workspace ID (GUID) if it's a full resource ID
        ws_short_id = ws_id.split('/')[-1] if '/' in ws_id else ws_id
        if ws_short_id not in workspaces_to_query:
            workspaces_to_query[ws_short_id] = []
        workspaces_to_query[ws_short_id].append(nsg_id)

    logger.info(f"Identified {len(workspaces_to_query)} unique workspaces to query.")
    return workspaces_to_query


def generate_kql_query(target_ip: str, start_time_dt: datetime, end_time_dt: datetime, nsg_ids_for_ws: Optional[List[str]] = None) -> str:
    """
    Generates a KQL query for NSG flow logs (AzureNetworkAnalytics_CL) for a specific time window.
    Optionally filters by a list of NSG IDs relevant to the target workspace.
    """
    table_name = "AzureNetworkAnalytics_CL"
    start_time_str = start_time_dt.strftime('%Y-%m-%dT%H:%M:%SZ')
    end_time_str = end_time_dt.strftime('%Y-%m-%dT%H:%M:%SZ')

    query_parts = [
        table_name,
        f"| where TimeGenerated between (datetime('{start_time_str}') .. datetime('{end_time_str}'))",
        f'| where FlowStatus_s == "A"', # Allowed flows
        f'| where SrcIP_s == "{target_ip}" or DestIP_s == "{target_ip}"'
    ]

    # Add NSG filter if specific NSG IDs are provided for this workspace query
    if nsg_ids_for_ws:
        nsg_names = set()
        for nsg_id in nsg_ids_for_ws:
            try:
                nsg_name = nsg_id.split('/')[-1]
                nsg_names.add(nsg_name)
            except Exception:
                logger.warning(f"Could not extract NSG name from ID '{nsg_id}' for query filter.")
        if nsg_names:
            # Create an 'in' clause for multiple NSG names
            nsg_names_str = '","'.join(nsg_names)
            query_parts.append(f'| where NSGList_s in ("{nsg_names_str}")') # Filter by NSG Name

    # Projection and Ordering
    query_parts.extend([
        "| project TimeGenerated, FlowDirection_s, SrcIP_s, DestIP_s, DestPort_d, FlowStatus_s, L7Protocol_s, InboundBytes_d, OutboundBytes_d, NSGList_s",
        "| order by TimeGenerated desc"
    ])

    full_query = "\n".join(query_parts)
    logger.debug(f"Generated KQL Query:\n{full_query}")
    return full_query.strip()


def execute_and_save_kql(workspace_id: str, kql_query: str, target_ip: str, time_range_label: str) -> Optional[pd.DataFrame]:
    """
    Executes a KQL query against a Log Analytics workspace and returns results as a Pandas DataFrame.
    Handles errors and logs appropriately. Saves raw output on JSON decode failure.
    """
    logger.info(f"Executing KQL query for Workspace {workspace_id} ({time_range_label})...")

    # Use workspace short ID for the command
    workspace_short_id = workspace_id.split('/')[-1] if '/' in workspace_id else workspace_id

    # Escape potential special characters in the query for the command line
    # For complex queries, using a temp file might be safer, but trying direct first for simplicity
    # Basic escaping for quotes:
    escaped_kql = kql_query.replace('"', '\\"')

    # Construct Azure CLI command (attempting direct query string)
    # Note: Complex queries might hit shell limits. Consider temp file approach if issues arise.
    cmd = f'az monitor log-analytics query --workspace "{workspace_short_id}" --analytics-query "{escaped_kql}" -o json --timeout {DEFAULT_TIMEOUT}'
    logger.debug(f"Executing command: {cmd}")

    query_results_json = run_command(cmd) # run_command handles basic execution errors/timeout/JSON parsing

    if query_results_json is None:
        logger.error(f"KQL query execution failed or returned invalid data for Workspace {workspace_id} ({time_range_label}).")
        return None # Error already logged by run_command

    # Process results if query execution was successful
    try:
        # Standard format is {"tables": [{"name": "PrimaryResult", "columns": [...], "rows": [...]}]}
        if isinstance(query_results_json.get('tables'), list) and len(query_results_json['tables']) > 0:
            table = query_results_json['tables'][0]
            if isinstance(table.get('rows'), list) and len(table['rows']) > 0:
                columns = [col['name'] for col in table['columns']]
                rows = table['rows']
                df = pd.DataFrame(rows, columns=columns)
                record_count = len(df)
                logger.info(f"Query for Workspace {workspace_id} ({time_range_label}) returned {record_count} records.")
                return df
            else:
                logger.info(f"Query for Workspace {workspace_id} ({time_range_label}) returned 0 records.")
                return pd.DataFrame() # Return empty DataFrame for no records
        elif isinstance(query_results_json, list): # Handle direct array output if necessary
             logger.warning(f"Query for Workspace {workspace_id} ({time_range_label}) returned a JSON array directly. Processing...")
             if len(query_results_json) > 0:
                 df = pd.DataFrame(query_results_json)
                 logger.info(f"Processed {len(df)} records from direct JSON array.")
                 return df
             else:
                 logger.info(f"Query for Workspace {workspace_id} ({time_range_label}) returned an empty JSON array.")
                 return pd.DataFrame()
        else:
            logger.warning(f"Query result for Workspace {workspace_id} ({time_range_label}) has unexpected structure: {type(query_results_json)}")
            return None # Unexpected structure

    except Exception as e:
        logger.exception(f"Error processing KQL results into DataFrame for Workspace {workspace_id} ({time_range_label}): {e}")
        return None


def save_to_excel(df: pd.DataFrame, base_filename: str) -> Optional[str]:
    """Saves a DataFrame to an Excel file in the RESULTS_DIR."""
    if df.empty:
        logger.info(f"DataFrame is empty, skipping Excel save for {base_filename}.")
        return None

    excel_path = os.path.join(RESULTS_DIR, f"{base_filename}.xlsx")

    try:
        import openpyxl # Ensure engine is available
    except ImportError:
        logger.error("Module 'openpyxl' not found. Cannot save to Excel. Run: pip install openpyxl")
        print("ERROR: Module 'openpyxl' not found. Cannot save to Excel. Please install it.", file=sys.stderr)
        return None

    try:
        # Prepare DataFrame for Excel (handle timezones)
        df_to_export = df.copy()
        for col in df_to_export.select_dtypes(include=['datetime64[ns, UTC]', 'datetime64[ns, tz]']).columns:
             logger.debug(f"Converting timezone-aware column '{col}' to naive UTC for Excel.")
             try:
                 df_to_export[col] = df_to_export[col].dt.tz_convert('UTC').dt.tz_localize(None)
             except Exception as tz_err:
                 logger.warning(f"Could not convert timezone for column '{col}': {tz_err}. Saving as string.")
                 df_to_export[col] = df_to_export[col].astype(str) # Fallback to string

        # Define desired column order
        desired_order = [
            'TimeGenerated', 'FlowDirection_s', 'SrcIP_s', 'DestIP_s', 'DestPort_d',
            'FlowStatus_s', 'L7Protocol_s', 'InboundBytes_d', 'OutboundBytes_d','NSGList_s'
        ]
        # Get existing columns and create the final order
        existing_columns = df_to_export.columns.tolist()
        final_columns = [col for col in desired_order if col in existing_columns]
        final_columns.extend([col for col in existing_columns if col not in final_columns])
        df_to_export = df_to_export[final_columns] # Reorder

        logger.info(f"Writing {len(df_to_export)} records to Excel: {excel_path}")
        df_to_export.to_excel(excel_path, index=False, engine='openpyxl')
        print(f"SUCCESS: Consolidated results saved to: {excel_path}")
        return excel_path
    except Exception as e:
        logger.exception(f"Error saving DataFrame to Excel file {excel_path}: {e}")
        print(f"ERROR: Failed to save Excel file. Check log: {log_file_path}", file=sys.stderr)
        return None

# --- Main Execution Logic ---

def main():
    parser = argparse.ArgumentParser(description="Simplified Azure NSG Flow Log Analyzer. Finds NSGs for an IP, queries logs, and outputs to Excel.")
    parser.add_argument("ip_address", help="The target IP address to analyze.")
    parser.add_argument("--time-range", type=int, default=24, help="Time range in hours for the KQL query (default: 24)")
    # Removed --filter-nsg, --execute, --batch-hours, --timeout (using constant)

    args = parser.parse_args()
    target_ip = args.ip_address
    time_range_hours = args.time_range

    logger.info(f"--- Script execution started ---")
    logger.info(f"Target IP: {target_ip}")
    logger.info(f"Time Range: {time_range_hours} hours")

    # 1. Validate IP address format
    try:
        ipaddress.ip_address(target_ip)
    except ValueError:
        logger.error(f"Invalid IP address format provided: {target_ip}")
        print(f"ERROR: Invalid IP address format: {target_ip}", file=sys.stderr)
        sys.exit(1)

    # 2. Check Azure CLI login
    try:
        logger.info("Checking Azure CLI login status...")
        subprocess.run("az account show", shell=True, check=True, capture_output=True, text=True, encoding='utf-8', timeout=30)
        logger.info("Azure CLI login verified.")
    except subprocess.TimeoutExpired:
         logger.error("Azure CLI login check timed out. Please ensure 'az account show' runs quickly.")
         print("ERROR: Azure CLI login check timed out.", file=sys.stderr)
         sys.exit(1)
    except subprocess.CalledProcessError:
        logger.error("Azure CLI login required. Please run 'az login'.")
        print("ERROR: Azure CLI login required. Please run 'az login' and try again.", file=sys.stderr)
        sys.exit(1)
    except FileNotFoundError:
         logger.error("Azure CLI ('az') command not found.")
         print("ERROR: Azure CLI ('az') command not found. Please ensure it's installed and in your PATH.", file=sys.stderr)
         sys.exit(1)
    except Exception as e:
        logger.exception(f"An unexpected error occurred during Azure CLI check: {e}")
        print(f"ERROR: An unexpected error occurred during Azure CLI check. Check log: {log_file_path}", file=sys.stderr)
        sys.exit(1)


    # 3. Find related NSGs and group by Workspace
    workspaces_to_query = find_related_nsgs_and_workspaces(target_ip)

    if not workspaces_to_query:
        logger.warning("No workspaces found to query based on NSG flow log configurations for the IP.")
        print("INFO: No workspaces found to query. Exiting.")
        sys.exit(0) # Not an error, just nothing to query

    # 4. Define time range for queries
    overall_end_time = datetime.now(timezone.utc)
    overall_start_time = overall_end_time - timedelta(hours=time_range_hours)
    time_range_label = f"{time_range_hours}h" # Simple label for now

    # 5. Execute KQL queries per workspace and collect results
    all_results_df_list = []
    query_errors = 0
    for workspace_id, nsg_ids_in_ws in workspaces_to_query.items():
        logger.info(f"\nQuerying Workspace: {workspace_id} (for {len(nsg_ids_in_ws)} NSGs: {', '.join(nsg_ids_in_ws)})")
        kql_query = generate_kql_query(
            target_ip=target_ip,
            start_time_dt=overall_start_time,
            end_time_dt=overall_end_time,
            nsg_ids_for_ws=nsg_ids_in_ws # Pass the list of NSGs for this workspace
        )

        df_result = execute_and_save_kql(workspace_id, kql_query, target_ip, time_range_label)

        if df_result is not None: # Includes empty DataFrame for success with 0 records
            if not df_result.empty:
                 # Add workspace ID for context if merging results later
                 df_result['WorkspaceID'] = workspace_id
                 all_results_df_list.append(df_result)
        else:
            query_errors += 1
            logger.error(f"Query failed for workspace {workspace_id}.")
            # Continue to next workspace

    # 6. Consolidate results and save to single Excel file
    if not all_results_df_list and query_errors == 0:
         logger.info("All queries completed successfully, but no flow log records were found.")
         print("INFO: Analysis completed, but no flow log records were found for the specified IP and time range.")
    elif not all_results_df_list and query_errors > 0:
         logger.error("Queries were executed with errors, and no data was retrieved.")
         print(f"ERROR: Query execution failed for {query_errors} workspace(s). No data to save. Check log: {log_file_path}", file=sys.stderr)
    elif all_results_df_list:
        logger.info(f"Consolidating results from {len(all_results_df_list)} successful query executions...")
        try:
            consolidated_df = pd.concat(all_results_df_list, ignore_index=True)
            logger.info(f"Total consolidated records: {len(consolidated_df)}")

            # Generate filename
            timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
            safe_ip = target_ip.replace('.', '_')
            excel_filename = f"flow_logs_{safe_ip}_{timestamp}"

            # Save the consolidated DataFrame
            saved_path = save_to_excel(consolidated_df, excel_filename)
            if saved_path:
                 logger.info(f"Successfully saved consolidated results to {saved_path}")
            else:
                 logger.error("Failed to save the consolidated Excel file.")
                 # Error message already printed by save_to_excel

        except Exception as e:
            logger.exception(f"Error consolidating or saving final Excel data: {e}")
            print(f"ERROR: Failed to consolidate or save final Excel file. Check log: {log_file_path}", file=sys.stderr)

    logger.info("--- Script execution finished ---")

if __name__ == "__main__":
    # Check for required dependencies first
    try:
        import pandas
        import openpyxl
    except ImportError as e:
        print(f"ERROR: Missing required Python package: {e.name}. Please install it.", file=sys.stderr)
        print(f"ERROR: You can likely install required packages using: pip install pandas openpyxl", file=sys.stderr)
        sys.exit(1)

    main()