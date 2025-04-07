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
    
    # Build the query parts (Reordered based on feedback)
    query_parts = [
        table_name,
        f"| where TimeGenerated between (datetime('{start_time_str}') .. datetime('{end_time_str}'))", # 1. Time filter
        f'| where FlowStatus_s == "A"', # 2. Status filter (like successful query)
        f'| where SrcIP_s == "{target_ip}" or DestIP_s == "{target_ip}"' # 3. IP filter
    ]
    
    # Add NSG filter if provided
    if nsg_id:
        # NSGList_s usually contains the NSG name, not the full ID. Extract name.
        try:
            nsg_name = nsg_id.split('/')[-1]
            query_parts.append(f'| where NSGList_s contains "{nsg_name}"') # 4. NSG filter (Use 'contains' for flexibility)
        except Exception:
             print_warning(f"Could not extract NSG name from ID '{nsg_id}' for query filter.")
    
    
    # Add projection and ordering (matching user requested order)
    query_parts.extend([
        "| project TimeGenerated, FlowDirection_s, SrcIP_s, DestIP_s, PublicIPs_s, DestPort_d, FlowStatus_s, L7Protocol_s, InboundBytes_d, OutboundBytes_d, NSGList_s", # Added PublicIPs_s
        "| order by TimeGenerated desc"
    ])
    
    # Join parts into a single query string
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
                        'TimeGenerated', 'FlowDirection_s', 'SrcIP_s', 'DestIP_s', 
                        'PublicIPs_s', 'DestPort_d', 'FlowStatus_s', 'L7Protocol_s', 
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
