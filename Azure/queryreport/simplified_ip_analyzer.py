import os
import sys
import json
import argparse
import subprocess
import ipaddress
import logging
import time  # Import time module for sleep
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
    max_retries = 3
    base_delay = 15 # seconds - Significantly increased base delay

    for attempt in range(max_retries):
        logger.info(f"Executing command (Attempt {attempt + 1}/{max_retries}): {cmd[:250]}...")
        try:
            process = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, encoding='utf-8')
            try:
                stdout, stderr = process.communicate(timeout=DEFAULT_TIMEOUT + 90) # Timeout per attempt
                returncode = process.returncode
            except subprocess.TimeoutExpired:
                process.kill()
                stdout, stderr = process.communicate() # Get output even on timeout
                logger.error(f"Command timed out on attempt {attempt + 1} after {DEFAULT_TIMEOUT + 90} seconds.")
                logger.error(f"Stderr (partial on timeout): {stderr.strip()}")
                # Consider retrying on timeout as well, or fail fast
                if attempt + 1 == max_retries:
                    print(f"ERROR: Command timed out after {max_retries} attempts. Check log: {log_file_path}", file=sys.stderr)
                    return None
                delay = base_delay * (2 ** attempt)
                logger.info(f"Retrying after {delay} seconds due to timeout...")
                time.sleep(delay)
                continue # Go to next retry iteration

            # --- Check for Rate Limiting or other errors ---
            if returncode != 0:
                stderr_lower = stderr.lower()
                # Check for specific throttling keywords
                if "throttled" in stderr_lower or "ratelimiting" in stderr_lower or "429" in stderr_lower:
                    logger.warning(f"Rate limiting detected on attempt {attempt + 1}. Stderr: {stderr.strip()}")
                    if attempt + 1 == max_retries:
                        logger.error(f"Command failed after {max_retries} attempts due to rate limiting.")
                        print(f"ERROR: Azure Rate Limiting persisted after {max_retries} retries. Try again later or reduce query frequency. Check log: {log_file_path}", file=sys.stderr)
                        return None
                    # Calculate exponential backoff delay
                    delay = base_delay * (2 ** attempt) + (attempt * 2) # Add some jitter
                    logger.info(f"Retrying after {delay:.2f} seconds due to rate limiting...")
                    time.sleep(delay)
                    continue # Go to next retry iteration
                else:
                    # Other command execution error
                    logger.error(f"Command failed on attempt {attempt + 1}. Return Code: {returncode}")
                    logger.error(f"Stderr: {stderr.strip()}")
                    print(f"ERROR: Command execution failed (Return Code: {returncode}). Check log for details: {log_file_path}", file=sys.stderr)
                    return None # Fail fast on non-throttling errors

            # --- Process Successful Output ---
            if not stdout.strip():
                logger.warning(f"Command executed successfully on attempt {attempt + 1} but returned no output.")
                return None # Treat no output as None

            cleaned_stdout = stdout.strip()
            if cleaned_stdout.startswith('\ufeff'):
                cleaned_stdout = cleaned_stdout[1:]

            try:
                parsed_json = json.loads(cleaned_stdout)
                logger.info(f"Command executed successfully and JSON parsed on attempt {attempt + 1}.")
                return parsed_json # Success!
            except json.JSONDecodeError as e:
                logger.error(f"Failed to decode JSON response on attempt {attempt + 1}: {e}")
                logger.error(f"Output that failed JSON parsing (first 1000 chars): {cleaned_stdout[:1000]}...")
                # Fail fast if JSON parsing fails, retrying likely won't help
                print(f"ERROR: Command output was not valid JSON. Check log for details: {log_file_path}", file=sys.stderr)
                return None

        except Exception as e:
            logger.exception(f"Unexpected error running command on attempt {attempt + 1}: {e}")
            # Fail fast on unexpected errors during execution
            print(f"ERROR: An unexpected error occurred running command. Check log: {log_file_path}", file=sys.stderr)
            return None

    # Should not be reached if logic is correct, but as a safeguard
    logger.error("Exited retry loop unexpectedly in run_command.")
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
    Finds NSGs related to the IP (via NICs and Subnets using consolidated Graph queries)
    and maps them to their Log Analytics Workspace IDs.
    Returns a dictionary mapping Workspace ID (short form) to a list of associated NSG IDs.
    """
    logger.info(f"Starting consolidated search for NSGs and Workspaces related to IP: {target_ip}")
    nsg_ids_found = set()
    workspace_map = {} # nsg_id -> workspace_id
    workspaces_to_query = {} # workspace_id_short -> [nsg_ids]
    processed_subnet_ids = set() # Keep track of subnets processed to avoid duplicate checks

    # --- Query 1: Find NICs by IP and their associated Subnet/NSG ---
    logger.info("Step 1: Finding network interfaces via IP (Graph Query 1/3)...")
    nic_query = f"""
    Resources
    | where type =~ 'microsoft.network/networkinterfaces'
    | where properties.ipConfigurations contains '{target_ip}'
    | project id, name, nsgId = tostring(properties.networkSecurityGroup.id), subnetId = tostring(properties.ipConfigurations[0].properties.subnet.id)
    """
    nic_cmd = f"az graph query -q \"{nic_query}\" --query \"data\" -o json"
    nics_result = run_command(nic_cmd)
    nic_subnet_ids = set() # Subnets associated with the found NICs

    if nics_result is not None and isinstance(nics_result, list):
        logger.info(f"Successfully retrieved NIC info. Found {len(nics_result)} NICs potentially associated with {target_ip}.")
        for nic in nics_result:
            nsg_id = nic.get('nsgId')
            if nsg_id:
                logger.debug(f"Found NSG directly from NIC '{nic.get('name')}': {nsg_id}")
                nsg_ids_found.add(nsg_id)
            subnet_id = nic.get('subnetId')
            if subnet_id:
                nic_subnet_ids.add(subnet_id)
                processed_subnet_ids.add(subnet_id) # Mark as processed
    else:
        logger.warning(f"Could not retrieve NIC info for {target_ip}, or query failed/returned no results.")

    # --- Query 2: Find all Subnets, check IP containment and get NSGs ---
    # This query also gets NSGs for subnets found via NICs in the previous step.
    logger.info("Step 2: Checking all subnets for IP containment and associated NSGs (Graph Query 2/3)...")
    subnet_query = """
    Resources
    | where type =~ 'microsoft.network/virtualnetworks/subnets'
    | project id, name, addressPrefix = properties.addressPrefix, addressPrefixes = properties.addressPrefixes, nsgId = tostring(properties.networkSecurityGroup.id)
    """
    subnets_cmd = f"az graph query -q \"{subnet_query}\" --query \"data\" -o json"
    all_subnets_result = run_command(subnets_cmd)

    if all_subnets_result is not None and isinstance(all_subnets_result, list):
        logger.info(f"Successfully retrieved all subnets ({len(all_subnets_result)}). Processing for IP containment and NSGs...")
        for subnet in all_subnets_result:
            subnet_id = subnet.get('id')
            nsg_id = subnet.get('nsgId')

            # Check 1: Is this a subnet associated with a found NIC?
            if subnet_id in nic_subnet_ids:
                if nsg_id:
                    logger.debug(f"Found NSG from NIC-associated subnet '{subnet.get('name')}': {nsg_id}")
                    nsg_ids_found.add(nsg_id)
                processed_subnet_ids.add(subnet_id) # Ensure it's marked processed

            # Check 2: Does this subnet's range contain the target IP? (Only if not already processed via NIC)
            if subnet_id not in processed_subnet_ids:
                prefixes = []
                if subnet.get('addressPrefix'):
                    prefixes.append(subnet['addressPrefix'])
                if isinstance(subnet.get('addressPrefixes'), list):
                    prefixes.extend(subnet['addressPrefixes'])

                for prefix in set(prefixes):
                    if prefix and ip_in_subnet(target_ip, prefix):
                        logger.debug(f"IP {target_ip} is within subnet '{subnet.get('name')}' range {prefix}")
                        if nsg_id:
                            logger.debug(f"Found NSG from containing subnet '{subnet.get('name')}': {nsg_id}")
                            nsg_ids_found.add(nsg_id)
                        processed_subnet_ids.add(subnet_id) # Mark as processed
                        break # Stop checking prefixes for this subnet once a match is found
    else:
        logger.warning("Could not retrieve the list of all subnets, or query failed.")


    # --- Check if any NSGs were found ---
    if not nsg_ids_found:
        logger.warning(f"No relevant NSGs found for IP {target_ip} after checking NICs and Subnets.")
        return {}

    logger.info(f"Total unique NSGs found potentially related to {target_ip}: {len(nsg_ids_found)} -> {list(nsg_ids_found)}")

    # --- Query 3: Get Flow Log config and Workspace ID for all found NSGs ---
    logger.info(f"Step 3: Getting Flow Log configurations for {len(nsg_ids_found)} NSGs (Graph Query 3/3)...")
    nsg_ids_list_str = '","'.join(nsg_ids_found) # Prepare list for Kusto 'in' operator
    flow_log_query = f"""
    Resources
    | where type =~ 'microsoft.network/networkwatchers/flowlogs'
    | where properties.targetResourceId in ('{nsg_ids_list_str}')
    | project targetResourceId = tostring(properties.targetResourceId), workspaceId=properties.flowAnalyticsConfiguration.networkWatcherFlowAnalyticsConfiguration.workspaceId, enabled=properties.enabled
    """
    flow_logs_cmd = f"az graph query -q \"{flow_log_query}\" --query \"data\" -o json"

    flow_logs_list = run_command(flow_logs_cmd)

    if flow_logs_list is not None: # Check if command succeeded
        if isinstance(flow_logs_list, list):
            logger.info(f"Successfully retrieved {len(flow_logs_list)} flow log configurations for the found NSGs.")
            for config in flow_logs_list: # <<< Start of the loop where 'continue' is valid
                nsg_id = config.get('targetResourceId')
                workspace_id = config.get('workspaceId') # <<< Corrected indentation
                enabled = config.get('enabled', False) # <<< Corrected indentation

                if not nsg_id or nsg_id not in nsg_ids_found:
                    logger.warning(f"Flow log config found for unknown/unexpected NSG: {nsg_id}")
                    continue # <<< Valid inside the loop

                if not enabled:
                    logger.warning(f"Flow logs are disabled for NSG: {nsg_id}")
                    continue # <<< Valid inside the loop; Skip disabled flow logs

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
        # else: # Removed the 'else' part of the warning
        #    logger.warning(f"Could not retrieve any flow log configurations for the found NSGs, or query failed.")


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

    query_results_json = run_command(cmd) # run_command now handles retries for throttling

    if query_results_json is None:
        logger.error(f"KQL query execution failed or returned invalid/no data after retries for Workspace {workspace_id} ({time_range_label}).")
        return None # Error already logged by run_command

    # Process results if query execution was successful
    logger.info(f"Successfully executed KQL query for Workspace {workspace_id} ({time_range_label}). Processing results...")
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