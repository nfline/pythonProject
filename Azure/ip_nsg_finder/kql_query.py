"""
This module handles KQL query generation and execution.
"""
import os
import subprocess
import json
import pandas as pd
from datetime import datetime, timedelta, timezone
from typing import Dict, Optional, List, Any

from .common import print_info, print_error, print_success, print_warning, ensure_output_dir
from .logging_utils import setup_logger

def generate_simple_kql_query(target_ip: str, time_range_hours: int = 24) -> str:
    """Generates a basic KQL query for NSG flow logs (AzureNetworkAnalytics_CL)."""
    # Calculate time range for query
    end_time = datetime.now(timezone.utc)
    start_time = end_time - timedelta(hours=time_range_hours)
    
    # Format times in ISO format for better compatibility
    start_time_str = start_time.strftime('%Y-%m-%dT%H:%M:%SZ')
    end_time_str = end_time.strftime('%Y-%m-%dT%H:%M:%SZ')
    
    # Basic query with IP filtering
    query = f"""AzureNetworkAnalytics_CL
| where TimeGenerated between (datetime('{start_time_str}') .. datetime('{end_time_str}'))
| where FlowType_s == "AzureNetworkAnalytics" # Ensure we are looking at flow logs
| where SrcIP_s == "{target_ip}" or DestIP_s == "{target_ip}"
| project TimeGenerated, FlowStartTime_t, FlowEndTime_t, FlowType_s, 
          SrcIP_s, DestIP_s, SrcPort_d, DestPort_d, 
          L4Protocol_s, L7Protocol_s, FlowDirection_s,
          NSGRule_s, NSG_s, TenantId, SubscriptionId
| order by TimeGenerated desc"""
          
    return query.strip()

def generate_kql_query(target_ip: str,
                       time_range_hours: int = 24, # Keep for default case
                       nsg_id: Optional[str] = None,
                       query_type: str = "standard", # Query type parameter
                       start_time_dt: Optional[datetime] = None,
                       end_time_dt: Optional[datetime] = None,
                       internet_only: bool = False) -> str: # Kept for backward compatibility
    """
    Generates a KQL query for NSG flow logs (AzureNetworkAnalytics_CL),
    optionally filtering by a specific NSG ID and allowing specific time windows.
    
    Parameters:
        target_ip: The IP address to filter traffic for
        time_range_hours: Number of hours to look back from current time (or from start_time_dt)
        nsg_id: Optional NSG resource ID to filter results
        query_type: Type of query to generate: "standard", "internet" (public IPs only), 
                    "intranet" (VNet traffic only), or "noninternet_nonintranet" (edge cases)
        start_time_dt: Optional explicit start time
        end_time_dt: Optional explicit end time
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
    
    # For backward compatibility - if internet_only is True, override query_type
    if internet_only:
        query_type = "internet"
        
    # Determine which query type to generate
    if query_type == "internet":
        # Internet Only KQL: Exclude all flows where SrcIP or DestIP is in VNetRanges/InternalExceptionRanges, then select flows with any public IP value, and expand all public IPs.
        kql_internet_only = fr'''
let VNetRanges = dynamic([]);
let InternalExceptionRanges = dynamic([]);
let isInVNet = (ip:string) {{ ipv4_is_in_any_range(ip, VNetRanges) }};
let isInExceptionRange = (ip:string) {{ ipv4_is_in_any_range(ip, InternalExceptionRanges) }};
{table_name}
| where TimeGenerated between (datetime('{start_time_str}') .. datetime('{end_time_str}'))
| where isInVNet(SrcIP_s) == false and isInVNet(DestIP_s) == false and isInExceptionRange(SrcIP_s) == false and isInExceptionRange(DestIP_s) == false
| where isnotempty(DestPublicIPs_s) or isnotempty(SrcPublicIPs_s)
| where SrcIP_s == "{target_ip}" or DestIP_s == "{target_ip}"
| extend DestPublicIPsClean = extract_all(@"([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)", DestPublicIPs_s)
| extend DestPublicIPsClean = array_strcat(DestPublicIPsClean, ",")
| extend SrcPublicIPsClean = extract_all(@"([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)", SrcPublicIPs_s)
| extend SrcPublicIPsClean = array_strcat(SrcPublicIPsClean, ",")
| project TimeGenerated, FlowDirection_s, SrcIP_s, SrcPublicIPsClean, DestIP_s, DestPublicIPsClean, DestPort_d, FlowStatus_s, L7Protocol_s, InboundBytes_d, OutboundBytes_d, NSGList_s
| order by TimeGenerated desc'''
        return kql_internet_only.strip()
    elif query_type == "intranet":
        # Intranet Traffic KQL: Only include flows where both source and destination IPs are in VNet ranges
        kql_intranet = fr'''
//**Report 1 - Intranet Traffic**
let VNetRanges = dynamic([
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16"
    // Add more VNet CIDR ranges in quotes, separated by commas
]);
// Helper function to check if an IP is in ANY of the VNet ranges
let IsInVNet = (ip_string:string) {{
    ipv4_is_in_any_range(ip_string, VNetRanges)
}};

{table_name}
| where TimeGenerated between (datetime('{start_time_str}') .. datetime('{end_time_str}'))
| extend PublicSrcIPs = iif(isnotempty(SrcPublicIPs_s), split(SrcPublicIPs_s, ","), dynamic(["-"]))
| extend PublicDestIPs = iif(isnotempty(DestPublicIPs_s), split(DestPublicIPs_s, ","), dynamic(["-"]))
| mv-expand PublicSrcIP = tostring(split(iif(PublicSrcIPs[0] != "-", tostring(PublicSrcIPs[0]), "-"), "|")[0]) to typeof(string)
| mv-expand PublicDestIP = tostring(split(iif(PublicDestIPs[0] != "-", tostring(PublicDestIPs[0]), "-"), "|")[0]) to typeof(string)
| extend Source_IP = iif(isnotempty(SrcPublicIPs_s), PublicSrcIP, SrcIP_s)
| extend Destination_IP = iif(isnotempty(DestPublicIPs_s), PublicDestIP, DestIP_s)

| where SrcIP_s == "{target_ip}" or DestIP_s == "{target_ip}"

// Filter: Source IP is in VNet AND Destination IP is in VNet
| where IsInVNet(Source_IP) and IsInVNet(Destination_IP)

// Extract just the NSG name from the full ID
| extend NSGName_s = tostring(split(NSGList_s, "/")[-1])

// Summarize blocks
| summarize 
    SumFlows = count(),                        // Total flow log entries for this source-dest pair (across all ports)
    PortUsed = make_set(DestPort_d),           // Create a list of unique destination ports used
    Dest_IP = make_set(Destination_IP),        // Create a list of unique destination addresses 
    FirstSeen = min(TimeGenerated),            // First time this source-dest pair was seen (on any port)
    LastSeen = max(TimeGenerated)              // Last time this source-dest pair was seen (on any port)
    by Source_IP, Destination_IP, L7Protocol_s, FlowDirection_s, FlowStatus_s, NSGName_s
| order by NSGName_s, Source_IP asc'''
        return kql_intranet.strip()
    
    elif query_type == "noninternet_nonintranet":
        # Non-Internet, Non-Intranet Traffic KQL: Find traffic that doesn't match either Internet or Intranet criteria
        kql_noninternet_nonintranet = fr'''
//**Report 3 - Not Internet or Intranet Traffic**

// *** DEFINE YOUR VNET RANGES HERE ***
let VNetRanges = dynamic([
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16"
    // Add more VNet CIDR ranges in quotes, separated by commas
]);

// Define the specific public ranges treated as internal
let InternalExceptionRanges = dynamic([
    # "1.1.0.0/16",
    # "2.2.0.0/16"
]);

// Helper function to check if an IP is in ANY of the VNet ranges
let IsInVNet = (ip_string:string) {{
    ipv4_is_in_any_range(ip_string, VNetRanges)
}};

// Helper function to check if an IP is in ANY of the Exception ranges
let IsInExceptionRange = (ip_string:string) {{
    ipv4_is_in_any_range(ip_string, InternalExceptionRanges)
}};

// Main Query
{table_name}
| where TimeGenerated between (datetime('{start_time_str}') .. datetime('{end_time_str}'))
| extend PublicSrcIPs = iif(isnotempty(SrcPublicIPs_s), split(SrcPublicIPs_s, ","), dynamic(["-"]))
| extend PublicDestIPs = iif(isnotempty(DestPublicIPs_s), split(DestPublicIPs_s, ","), dynamic(["-"]))
| mv-expand PublicSrcIP = tostring(split(iif(PublicSrcIPs[0] != "-", tostring(PublicSrcIPs[0]), "-"), "|")[0]) to typeof(string)
| mv-expand PublicDestIP = tostring(split(iif(PublicDestIPs[0] != "-", tostring(PublicDestIPs[0]), "-"), "|")[0]) to typeof(string)
| extend Source_IP = iif(isnotempty(SrcPublicIPs_s), PublicSrcIP, SrcIP_s)
| extend Destination_IP = iif(isnotempty(DestPublicIPs_s), PublicDestIP, DestIP_s)

| where SrcIP_s == "{target_ip}" or DestIP_s == "{target_ip}"

// Filter: Source IP is in VNet
| where IsInVNet(Source_IP)

// AND Destination IP meets the criteria:
// (Is NEITHER Public AND NOT InternalExc) OR (Is in Exception Range)
| where (IsInVNet(Destination_IP) == true and not(IsInExceptionRange(Destination_IP)))
    or IsInExceptionRange(Destination_IP)

// ***Extract just the NSG name from the full ID***
| extend NSGName_s = tostring(split(NSGList_s, "/")[-1])

// ***Summarize blocks***
| summarize 
    SumFlows = count(),                        // Total flow log entries for this source-dest pair (across all ports)
    PortUsed = make_set(DestPort_d),           // Create a list of unique destination ports used
    Dest_IP = make_set(Destination_IP),        // Create a list of unique destination addresses 
    FirstSeen = min(TimeGenerated),            // First time this source-dest pair was seen (on any port)
    LastSeen = max(TimeGenerated)              // Last time this source-dest pair was seen (on any port)
    by Source_IP, Destination_IP, L7Protocol_s, FlowDirection_s, FlowStatus_s, NSGName_s
| order by NSGName_s, NSGName_s, Source_IP asc'''
        return kql_noninternet_nonintranet.strip()
    
    else:  # standard query type
        # Build the query parts (all comments in English)
        query_parts = [
            table_name,
            f"| where TimeGenerated between (datetime('{start_time_str}') .. datetime('{end_time_str}'))", # 1. Filter by time range
            # f'| where FlowStatus_s == "A"', # 2. Only successful flows
            f'| where SrcIP_s == "{target_ip}" or DestIP_s == "{target_ip}"' # 3. Filter by target IP
        ]
        # Add NSG filter if provided
        if nsg_id:
            try:
                nsg_name = nsg_id.split('/')[-1]
                query_parts.append(f'| where NSGList_s contains "{nsg_name}"') # 4. Filter by NSG name
            except Exception:
                print_warning(f"Could not extract NSG name from ID '{nsg_id}' for query filter.")
        # Expand all public IPs for consistent output
        query_parts.extend([
            "| extend DestPublicIPsClean = extract_all(@\"([0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+)\", DestPublicIPs_s)",
            "| extend DestPublicIPsClean = array_strcat(DestPublicIPsClean, \",\")",
            "| extend SrcPublicIPsClean = extract_all(@\"([0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+)\", SrcPublicIPs_s)",
            "| extend SrcPublicIPsClean = array_strcat(SrcPublicIPsClean, \",\")",
            "| project TimeGenerated, FlowDirection_s, SrcIP_s, SrcPublicIPsClean, DestIP_s, DestPublicIPsClean, DestPort_d, FlowStatus_s, L7Protocol_s, InboundBytes_d, OutboundBytes_d, NSGList_s",
            "| order by TimeGenerated desc"
        ])
        # Join all parts into a single query string
        full_query = "\n".join(query_parts)
        return full_query.strip()

def execute_kql_query(workspace_id: str, kql_query: str, target_ip: str, nsg_id: str, 
                     timeout_seconds: int = 180, subscription_id: Optional[str] = None) -> Optional[Dict]:
    """Execute a KQL query against a Log Analytics workspace, save results to Excel, and log execution."""

    # --- Logging Setup ---
    output_dir = ensure_output_dir()
    log_dir = os.path.join(output_dir, "logs")
    os.makedirs(log_dir, exist_ok=True)
    # Log file name based on IP and Date
    log_file_name = f"query_log_{target_ip.replace('.', '_')}_{datetime.now().strftime('%Y%m%d')}.log"
    log_file_path = os.path.join(log_dir, log_file_name)
    # Using file path is sufficient for logger name uniqueness
    logger = setup_logger(log_file_path)  # Setup ensures directory exists

    nsg_name = nsg_id.split('/')[-1]  # For logging clarity
    logger.info(f"--- Starting KQL Query Execution ---")
    logger.info(f"Target IP: {target_ip}")
    logger.info(f"NSG Name: {nsg_name}")
    logger.info(f"Workspace ID: {workspace_id}")
    logger.info(f"Timeout Seconds: {timeout_seconds}")
    if subscription_id:
        logger.info(f"Using Subscription ID: {subscription_id}")

    # --- KQL Query Preparation ---
    kql_query = kql_query.strip()
    logger.debug(f"KQL Query:\n{kql_query}")  # Log full query at debug level

    # Make sure workspace ID is just the ID, not the full resource path
    if '/' in workspace_id:
        workspace_short_id = workspace_id.split('/')[-1]
        logger.info(f"Using Workspace ID (short): {workspace_short_id}")
    else:
        workspace_short_id = workspace_id  # Assume it's already the short ID

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
    # Add subscription parameter if provided
    subscription_param = f" --subscription {subscription_id}" if subscription_id else ""
    cmd = f"az monitor log-analytics query --workspace \"{workspace_short_id}\"{subscription_param} --analytics-query \"@{temp_query_file}\" -o json"
    
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
        cli_timeout = timeout_seconds + 60  # Add 60s buffer for CLI startup/JSON parsing etc.
        logger.info(f"Waiting for command with timeout: {cli_timeout} seconds")
        
        try:
            stdout, stderr = process.communicate(timeout=cli_timeout)
            returncode = process.returncode
        except subprocess.TimeoutExpired:
            process.kill()
            stdout, stderr = process.communicate()
            logger.error(f"KQL query timed out after {cli_timeout} seconds!")
            print_error(f"KQL query timed out after {cli_timeout} seconds!")
            return None
        
        # Check the return code and handle errors
        if returncode != 0:
            logger.error(f"KQL query failed with error (code {returncode}): {stderr}")
            print_error(f"KQL query failed with error (code {returncode}): {stderr}")
            return None
        
        # Process successful result
        if not stdout.strip():
            logger.warning("KQL query returned no data")
            print_warning("KQL query returned no data")
            return None
        
        # Try to parse JSON result
        try:
            results = json.loads(stdout)
            logger.info(f"Query returned {len(results)} results")
            
            # Save raw results
            results_file = os.path.join(output_dir, f"query_results_{target_ip}_{nsg_name}_{timestamp}.json")
            with open(results_file, 'w', encoding='utf-8') as f:
                json.dump(results, f, indent=2)
            logger.info(f"Saved raw query results to {results_file}")
            
            # Try to convert to DataFrame and save as Excel
            if results:
                try:
                    # Convert to DataFrame
                    df = pd.DataFrame(results)
                    
                    # Define expected column order based on KQL query in generate_kql_query
                    # This ensures the Excel file columns match the order in the query
                    expected_columns = [
                        'TimeGenerated', 'FlowDirection_s', 'SrcIP_s', 'SrcPublicIPs_s', 'SrcPublicIPsClean',
                        'DestIP_s', 'DestPublicIPsClean', 'DestPort_d', 'FlowStatus_s', 'L7Protocol_s', 
                        'InboundBytes_d', 'OutboundBytes_d', 'NSGList_s'
                    ]
                    
                    # Reorder columns if they exist in DataFrame
                    existing_columns = [col for col in expected_columns if col in df.columns]
                    # Add any columns from DataFrame that weren't in our expected list (if any)
                    other_columns = [col for col in df.columns if col not in expected_columns]
                    # Create final ordered column list
                    ordered_columns = existing_columns + other_columns
                    
                    # Reorder the DataFrame columns
                    df = df[ordered_columns]
                    
                    excel_file = os.path.join(output_dir, f"query_results_{target_ip}_{nsg_name}_{timestamp}.xlsx")
                    df.to_excel(excel_file, index=False, engine='openpyxl')
                    logger.info(f"Saved query results to Excel: {excel_file}")
                    print_success(f"Query results saved to Excel: {excel_file}")
                except Exception as e:
                    logger.error(f"Error saving results to Excel: {e}")
                    print_error(f"Error saving results to Excel: {e}")
            
            return results
            
        except json.JSONDecodeError as e:
            logger.error(f"Error parsing query results as JSON: {e}")
            logger.debug(f"Raw output: {stdout[:1000]}...")  # Limited to avoid excessive logging
            print_error(f"Error parsing query results as JSON: {e}")
            
            # Save raw output for debugging
            raw_file = os.path.join(output_dir, f"raw_output_{target_ip}_{nsg_name}_{timestamp}.txt")
            with open(raw_file, 'w', encoding='utf-8') as f:
                f.write(stdout)
            logger.info(f"Saved raw non-JSON output to {raw_file}")
            print_info(f"Saved raw non-JSON output to {raw_file}")
            
            return None
            
    except Exception as e:
        logger.error(f"Unexpected error running KQL query: {e}")
        print_error(f"Unexpected error running KQL query: {e}")
        if process and process.poll() is None:
            process.kill()  # Ensure process is killed if it's still running
        return None
    finally:
        # Cleanup: remove temporary query file (optional)
        try:
            # Uncomment to enable cleanup
            # os.remove(temp_query_file)
            # logger.info(f"Removed temporary query file {temp_query_file}")
            pass  # Keep temporary file for debugging
        except OSError:
            pass
