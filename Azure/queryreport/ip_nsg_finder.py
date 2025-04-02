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
import re
from datetime import datetime, timedelta, timezone
from typing import List, Dict, Any, Optional, Tuple

# Fix console encoding issues on Windows
if sys.stdout.encoding != 'utf-8':
    try:
        # On Windows, try to fix console encoding issues
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    except AttributeError:
        # Python 3.6 or earlier doesn't have reconfigure method
        pass

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
    try:
        os.makedirs(os.path.dirname(file_path), exist_ok=True)
        with open(file_path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        print_info(f"Data saved to {file_path}")
    except Exception as e:
        print_error(f"Error saving JSON data: {str(e)}")

def run_command(cmd: str) -> Optional[Dict]:
    """Run command and return JSON result"""
    try:
        print_info(f"Executing command: {cmd}")
        result = subprocess.run(
            cmd, 
            shell=True, 
            capture_output=True, 
            text=True, 
            encoding='utf-8',  # Ensure UTF-8 encoding
            errors='replace',  # Replace invalid characters instead of failing
            check=False
        )
        
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
    # PT60M = 60 minutes format required by Azure
    timespan_param = f"PT{timeout_seconds}M"
    
    # Create a temporary file with the query to avoid command line length issues
    temp_query_file = os.path.join("output", "temp_query.kql")
    os.makedirs("output", exist_ok=True)
    with open(temp_query_file, 'w', encoding='utf-8') as f:
        f.write(kql_query)
    
    # Log query details to help with debugging
    log_file = os.path.join("output", "kql_commands.log")
    with open(log_file, 'a', encoding='utf-8') as f:
        f.write(f"\n\n--- QUERY EXECUTION: {datetime.now(timezone.utc)} ---\n")
        f.write(f"Workspace ID: {workspace_id}\n")
        f.write(f"Timespan: {timespan_param}\n")
        f.write(f"Query:\n{kql_query}\n")
    
    # Construct Azure CLI command with proper parameters
    # Use --query parameter to process results properly
    cmd = f"az monitor log-analytics query --workspace {workspace_id} --analytics-query \"@{temp_query_file}\" --timespan {timespan_param} -o json"
    
    print_info(f"Query command: {cmd}")
    # Log the full command
    with open(log_file, 'a', encoding='utf-8') as f:
        f.write(f"Command: {cmd}\n")
    
    # Execute the query with extended timeout
    try:
        process = subprocess.Popen(
            cmd, 
            shell=True, 
            stdout=subprocess.PIPE, 
            stderr=subprocess.PIPE,
            text=True,
            encoding='utf-8',
            errors='replace'  # Replace invalid characters instead of failing
        )
        
        # Wait with timeout (3x the query timeout to allow for processing)
        stdout, stderr = process.communicate(timeout=timeout_seconds * 3)
        
        # Log the output
        with open(log_file, 'a', encoding='utf-8') as f:
            f.write(f"ReturnCode: {process.returncode}\n")
            f.write(f"StdErr: {stderr}\n")
            if len(stdout) > 1000:
                f.write(f"StdOut (truncated): {stdout[:1000]}...\n")
            else:
                f.write(f"StdOut: {stdout}\n")
        
        if process.returncode != 0:
            # Check if it's a response size error
            if "ResponseSizeError" in stderr or "Response size too large" in stderr:
                print_error("Query result exceeded maximum size limit. Trying with more restrictive filters...")
                
                # Create a more restrictive query by adding time constraints or reducing limit
                if "limit" in kql_query.lower():
                    # Reduce the limit if it exists
                    current_limit = int(re.search(r'limit\s+(\d+)', kql_query.lower()).group(1))
                    new_limit = max(10, current_limit // 10)  # Reduce by factor of 10, but minimum 10
                    new_query = re.sub(r'limit\s+\d+', f'limit {new_limit}', kql_query)
                else:
                    # Add a limit if it doesn't exist
                    new_query = kql_query + "\n| limit 20"
                
                print_info(f"Retrying with more restrictive query (limit reduced)")
                with open(temp_query_file, 'w', encoding='utf-8') as f:
                    f.write(new_query)
                
                # Log retry information
                with open(log_file, 'a', encoding='utf-8') as f:
                    f.write(f"Retrying with reduced limit. New query:\n{new_query}\n")
                
                # Try again with the more restrictive query
                retry_cmd = f"az monitor log-analytics query --workspace {workspace_id} --analytics-query \"@{temp_query_file}\" --timespan {timespan_param} -o json"
                retry_process = subprocess.Popen(
                    retry_cmd,
                    shell=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    encoding='utf-8',
                    errors='replace'  # Replace invalid characters instead of failing
                )
                stdout, stderr = retry_process.communicate(timeout=timeout_seconds * 3)
                
                # Log retry results
                with open(log_file, 'a', encoding='utf-8') as f:
                    f.write(f"Retry ReturnCode: {retry_process.returncode}\n")
                    f.write(f"Retry StdErr: {stderr}\n")
                    if len(stdout) > 1000:
                        f.write(f"Retry StdOut (truncated): {stdout[:1000]}...\n")
                    else:
                        f.write(f"Retry StdOut: {stdout}\n")
                
                if retry_process.returncode != 0:
                    # Handle semantic error
                    if "SemanticError" in stderr:
                        print_error(f"Semantic error: The table or column might not exist. See log file for details: {log_file}")
                        # Try a simple query to check table existence
                        simplest_query = """
// Check table existence
search "AzureNetworkAnalytics_CL" or "NetworkMonitoring"
| limit 5
"""
                        with open(temp_query_file, 'w', encoding='utf-8') as f:
                            f.write(simplest_query)
                            
                        with open(log_file, 'a', encoding='utf-8') as f:
                            f.write(f"Trying simplest query to check table existence:\n{simplest_query}\n")
                            
                        check_cmd = f"az monitor log-analytics query --workspace {workspace_id} --analytics-query \"@{temp_query_file}\" --timespan {timespan_param} -o json"
                        check_process = subprocess.Popen(
                            check_cmd,
                            shell=True,
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE,
                            text=True,
                            encoding='utf-8',
                            errors='replace'  # Replace invalid characters instead of failing
                        )
                        check_stdout, check_stderr = check_process.communicate(timeout=timeout_seconds * 3)
                        
                        with open(log_file, 'a', encoding='utf-8') as f:
                            f.write(f"Check ReturnCode: {check_process.returncode}\n")
                            f.write(f"Check StdErr: {check_stderr}\n")
                            f.write(f"Check StdOut: {check_stdout}\n")
                    
                    print_error(f"Retry query failed: {stderr}")
                    return None
            elif "SemanticError" in stderr:
                print_error(f"Semantic error: The table or column might not exist")
                # Log error details
                with open(log_file, 'a', encoding='utf-8') as f:
                    f.write(f"SemanticError details: {stderr}\n")
                
                # Try to find available tables
                table_query = """
// Check available tables
search *
| summarize count() by $table
| order by count_ desc
| limit 10
"""
                with open(temp_query_file, 'w', encoding='utf-8') as f:
                    f.write(table_query)
                    
                with open(log_file, 'a', encoding='utf-8') as f:
                    f.write(f"Trying to find available tables:\n{table_query}\n")
                    
                table_cmd = f"az monitor log-analytics query --workspace {workspace_id} --analytics-query \"@{temp_query_file}\" --timespan {timespan_param} -o json"
                table_process = subprocess.Popen(
                    table_cmd,
                    shell=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    encoding='utf-8',
                    errors='replace'  # Replace invalid characters instead of failing
                )
                table_stdout, table_stderr = table_process.communicate(timeout=timeout_seconds * 3)
                
                with open(log_file, 'a', encoding='utf-8') as f:
                    f.write(f"Table search ReturnCode: {table_process.returncode}\n")
                    f.write(f"Table search StdErr: {table_stderr}\n")
                    if table_stdout.strip():
                        f.write(f"Available tables: {table_stdout}\n")
                
                return None
            else:
                print_error(f"Query execution failed: {stderr}")
                return None
        
        if not stdout.strip():
            print_warning("Query executed successfully but returned no data")
            return []
        
        try:
            results = json.loads(stdout)
            if not results:
                print_warning("Query returned empty results")
                return []
            
            # Save results
            output_dir = "output"
            os.makedirs(output_dir, exist_ok=True)
            
            workspace_short_id = workspace_id.split('/')[-1] if '/' in workspace_id else workspace_id
            result_path = os.path.join(output_dir, f"query_results_{workspace_short_id}.json")
            
            save_json(results, result_path)
            print_success(f"Query results saved to {result_path}")
            
            # Print summary
            result_count = len(results) if isinstance(results, list) else 0
            print_success(f"Query returned {result_count} records")
            
            if result_count > 0:
                print_info("Sample records:")
                sample_size = min(3, result_count)
                for i in range(sample_size):
                    print(json.dumps(results[i], indent=2, ensure_ascii=False))
                    if i < sample_size - 1:
                        print("---")
            
            return results
        except json.JSONDecodeError as e:
            print_error(f"Failed to parse query results: {e}")
            print_info(f"Raw output: {stdout[:500]}...")
            return None
    except subprocess.TimeoutExpired:
        print_error(f"Query execution timed out after {timeout_seconds*3} seconds")
        return None
    except Exception as e:
        print_error(f"Error executing query: {str(e)}")
        return None
    finally:
        # Clean up temp file
        if os.path.exists(temp_query_file):
            try:
                os.remove(temp_query_file)
            except:
                pass

def generate_simple_kql_query(target_ip: str, time_range_hours: int = 24) -> str:
    """Generate a simple KQL query without NSG filtering"""
    
    # Use timezone-aware objects for UTC time
    end_time = datetime.now(timezone.utc)
    start_time = end_time - timedelta(hours=time_range_hours)
    
    # Format times for KQL query - exactly as shown in screenshot
    start_time_str = start_time.strftime("%Y-%m-%dT%H:%M:%S.%f")[:23] + "Z"
    end_time_str = end_time.strftime("%Y-%m-%dT%H:%M:%S.%f")[:23] + "Z"
    
    # Modified KQL query with comments for debugging
    query = f"""
// KQL query parameters: IP={target_ip}, time range={time_range_hours} hours
// Using union operator for compatibility
union 
(AzureNetworkAnalytics_CL
| where TimeGenerated between (datetime({start_time_str}) .. datetime({end_time_str}))
| where FlowStatus_s == "A" 
| where SrcIP_s == "{target_ip}" or DestIP_s == "{target_ip}"),
(NetworkMonitoring 
| where TimeGenerated between (datetime({start_time_str}) .. datetime({end_time_str}))
| where SrcIP == "{target_ip}" or DestIP == "{target_ip}")
| project 
  TimeGenerated,
  FlowDirection_s = column_ifexists("FlowDirection_s", ""),
  SrcIP_s = column_ifexists("SrcIP_s", column_ifexists("SrcIP", "")),
  DestIP_s = column_ifexists("DestIP_s", column_ifexists("DestIP", "")),
  SrcPort_d = column_ifexists("SrcPort_d", column_ifexists("SrcPort", 0)),
  DestPort_d = column_ifexists("DestPort_d", column_ifexists("DestPort", 0)),
  Protocol_s = column_ifexists("Protocol_s", column_ifexists("Protocol", "")),
  FlowStatus_s = column_ifexists("FlowStatus_s", ""),
  L7Protocol_s = column_ifexists("L7Protocol_s", ""),
  InboundBytes_d = column_ifexists("InboundBytes_d", 0),
  OutboundBytes_d = column_ifexists("OutboundBytes_d", 0)
| sort by TimeGenerated desc
| limit 100
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
    
    # Use timezone-aware objects for UTC time
    end_time = datetime.now(timezone.utc)
    start_time = end_time - timedelta(hours=time_range_hours)
    
    # Format times for KQL query - exactly as shown in screenshot
    start_time_str = start_time.strftime("%Y-%m-%dT%H:%M:%S.%f")[:23] + "Z"
    end_time_str = end_time.strftime("%Y-%m-%dT%H:%M:%S.%f")[:23] + "Z"
    
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
        nsg_names_str = ""
        if filter_by_nsg and nsg_ids:
            nsg_names = []
            for nsg_id in nsg_ids:
                nsg_name = nsg_id.split('/')[-1]
                nsg_names.append(nsg_name)
            
            # Only add NSG filter if we have NSGs to filter
            if nsg_names:
                nsg_names_str = ", ".join([f'"{name}"' for name in nsg_names])
                # Modify NSG filtering syntax with column_ifexists to handle potentially missing fields
                nsg_filter = f"| where column_ifexists(\"NSGName_s\", \"\") in~ ({nsg_names_str})\n"
        
        # Modified KQL query with comments for debugging
        query = f"""
// KQL query parameters: IP={target_ip}, time range={time_range_hours} hours, NSG filter={nsg_names_str}
// Using union operator for compatibility
union 
(AzureNetworkAnalytics_CL
| where TimeGenerated between (datetime({start_time_str}) .. datetime({end_time_str}))
| where FlowStatus_s == "A" 
| where SrcIP_s == "{target_ip}" or DestIP_s == "{target_ip}"),
(NetworkMonitoring 
| where TimeGenerated between (datetime({start_time_str}) .. datetime({end_time_str}))
| where SrcIP == "{target_ip}" or DestIP == "{target_ip}")
{nsg_filter}| project 
  TimeGenerated,
  FlowDirection_s = column_ifexists("FlowDirection_s", ""),
  SrcIP_s = column_ifexists("SrcIP_s", column_ifexists("SrcIP", "")),
  DestIP_s = column_ifexists("DestIP_s", column_ifexists("DestIP", "")),
  SrcPort_d = column_ifexists("SrcPort_d", column_ifexists("SrcPort", 0)),
  DestPort_d = column_ifexists("DestPort_d", column_ifexists("DestPort", 0)),
  Protocol_s = column_ifexists("Protocol_s", column_ifexists("Protocol", "")),
  FlowStatus_s = column_ifexists("FlowStatus_s", ""),
  L7Protocol_s = column_ifexists("L7Protocol_s", ""),
  InboundBytes_d = column_ifexists("InboundBytes_d", 0),
  OutboundBytes_d = column_ifexists("OutboundBytes_d", 0)
| sort by TimeGenerated desc
| limit 100
"""
        
        # Create a short name for the workspace for filename
        workspace_short_id = workspace_id.split('/')[-1] if '/' in workspace_id else workspace_id
        
        # Save the query to a file
        query_filename = f"kql_query_{workspace_short_id}.kql"
        query_path = os.path.join(output_dir, query_filename)
        
        with open(query_path, 'w', encoding='utf-8') as f:
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
