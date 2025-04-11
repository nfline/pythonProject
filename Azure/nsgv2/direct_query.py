"""
This module provides optimized direct queries for IP traffic in NSG flow logs.
It simplifies the flow from IP to workspace_id and subscription_id discovery.
"""

import os
import json
import logging
import subprocess
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional, Any, Tuple, Set

# Import common utilities - ensure these are compatible
import sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from ip_nsg_finder.common import print_info, print_success, print_warning, print_error, ensure_output_dir, run_command, save_json
from ip_nsg_finder.logging_utils import setup_logger

def get_subscription_from_ip(target_ip: str) -> Optional[str]:
    """
    Get subscription ID directly from an IP using Azure Resource Graph.
    """
    print_info(f"Finding subscription for IP {target_ip}...")
    
    # Use Azure Resource Graph query to find NICs with this IP
    nic_cmd = f"az graph query -q \"Resources | where type =~ 'microsoft.network/networkinterfaces' | where properties.ipConfigurations contains '{target_ip}' | project subscriptionId\" --query \"data[].subscriptionId\" -o json"
    
    try:
        subscription_ids = run_command(nic_cmd)
        if subscription_ids and isinstance(subscription_ids, list) and len(subscription_ids) > 0:
            # Get the first unique subscription ID
            unique_subs = list(set(subscription_ids))
            if len(unique_subs) > 1:
                print_warning(f"Found multiple subscriptions: {unique_subs}. Using the first one: {unique_subs[0]}")
            
            print_success(f"Found subscription ID: {unique_subs[0]}")
            return unique_subs[0]
        else:
            print_warning(f"No subscription found for IP {target_ip}")
            return None
    except Exception as e:
        print_error(f"Error finding subscription for IP {target_ip}: {e}")
        return None

def get_workspace_for_ip(target_ip: str, subscription_id: Optional[str] = None) -> Dict[str, str]:
    """
    Get workspace IDs directly for an IP address.
    Returns a dictionary of workspace_id -> subscription_id pairs.
    """
    workspaces = {}
    
    # If subscription ID not provided, try to find it
    if not subscription_id:
        subscription_id = get_subscription_from_ip(target_ip)
        if not subscription_id:
            print_warning("Could not determine subscription ID, workspace discovery may be limited")
    
    # Find directly related NSGs using Azure Resource Graph
    print_info("Finding NSGs and associated flow logs...")
    
    # First, get NSGs from network interfaces
    nic_nsg_cmd = f"az graph query -q \"Resources | where type =~ 'microsoft.network/networkinterfaces' | where properties.ipConfigurations contains '{target_ip}' | extend nsgId = tostring(properties.networkSecurityGroup.id) | where isnotempty(nsgId) | project nsgId\" --query \"data[].nsgId\" -o json"
    
    nic_nsgs = []
    try:
        nic_nsgs = run_command(nic_nsg_cmd) or []
    except Exception as e:
        print_error(f"Error finding NSGs from NICs: {e}")
    
    # Next, get NSGs from subnets
    subnet_nsg_cmd = f"az graph query -q \"Resources | where type =~ 'microsoft.network/virtualnetworks/subnets' | extend nics = array_length(properties.ipConfigurations) | where nics > 0 | extend nsgId = tostring(properties.networkSecurityGroup.id) | where isnotempty(nsgId) | project nsgId\" --query \"data[].nsgId\" -o json"
    
    subnet_nsgs = []
    try:
        subnet_nsgs = run_command(subnet_nsg_cmd) or []
    except Exception as e:
        print_error(f"Error finding NSGs from subnets: {e}")
    
    # Combine and deduplicate NSG IDs
    all_nsgs = list(set(nic_nsgs + subnet_nsgs))
    
    if not all_nsgs:
        print_warning(f"No NSGs found for IP {target_ip}")
        return workspaces
    
    print_success(f"Found {len(all_nsgs)} NSGs potentially related to IP {target_ip}")
    
    # For each NSG, find associated flow logs and workspace
    subscription_param = f" --subscription {subscription_id}" if subscription_id else ""
    
    for nsg_id in all_nsgs:
        # Extract resource group and NSG name
        try:
            parts = nsg_id.split('/')
            resource_group = next(parts[i+1] for i, part in enumerate(parts) if part.lower() == 'resourcegroups')
            nsg_name = parts[-1]
            
            # Find flow log for this NSG
            flow_logs_cmd = f"az network watcher flow-log list{subscription_param} --query \"[?contains(targetResourceId, '{nsg_id}')].{{workspaceId:flowAnalyticsConfiguration.networkWatcherFlowAnalyticsConfiguration.workspaceId, workspaceResourceId:flowAnalyticsConfiguration.networkWatcherFlowAnalyticsConfiguration.workspaceResourceId, enabled:enabled}}\" -o json"
            
            flow_logs = run_command(flow_logs_cmd)
            if flow_logs and isinstance(flow_logs, list) and len(flow_logs) > 0:
                for flow_log in flow_logs:
                    if flow_log.get('enabled', False):
                        workspace_id = flow_log.get('workspaceId')
                        workspace_resource_id = flow_log.get('workspaceResourceId')
                        
                        if workspace_id and workspace_id not in workspaces:
                            workspaces[workspace_id] = subscription_id
                            print_success(f"Found workspace ID {workspace_id} for NSG {nsg_name}")
                        elif workspace_id:
                            print_info(f"Workspace ID {workspace_id} already found")
        except Exception as e:
            print_warning(f"Error processing NSG {nsg_id}: {e}")
    
    return workspaces

def generate_flow_query(target_ip: str, time_range_hours: int = 24) -> str:
    """
    Generate optimized KQL query for NSG flow logs.
    """
    # Calculate time range for query
    end_time = datetime.now(timezone.utc)
    start_time = end_time - timedelta(hours=time_range_hours)
    
    # Format times in ISO format
    start_time_str = start_time.strftime('%Y-%m-%dT%H:%M:%SZ')
    end_time_str = end_time.strftime('%Y-%m-%dT%H:%M:%SZ')
    
    # Optimized query with all necessary fields but without NSG filtering
    query = f"""AzureNetworkAnalytics_CL
| where TimeGenerated between (datetime('{start_time_str}') .. datetime('{end_time_str}'))
| where FlowStatus_s == "A" 
| where SrcIP_s == "{target_ip}" or DestIP_s == "{target_ip}"
| project TimeGenerated, FlowDirection_s, SrcIP_s, DestIP_s, PublicIPs_s, DestPort_d, 
         FlowStatus_s, L7Protocol_s, InboundBytes_d, OutboundBytes_d, NSGList_s
| order by TimeGenerated desc"""
          
    return query.strip()

def query_workspace(workspace_id: str, kql_query: str, subscription_id: Optional[str] = None, timeout_seconds: int = 180) -> Optional[List[Dict]]:
    """
    Execute a KQL query against a Log Analytics workspace.
    """
    # Prepare temp file for query
    output_dir = ensure_output_dir()
    temp_query_dir = os.path.join(output_dir, "temp_queries")
    os.makedirs(temp_query_dir, exist_ok=True)
    
    timestamp = datetime.now().strftime('%Y%m%d%H%M%S%f')
    temp_query_file = os.path.join(temp_query_dir, f"temp_query_{timestamp}.kql")
    
    try:
        with open(temp_query_file, 'w', encoding='utf-8') as f:
            f.write(kql_query)
    except IOError as e:
        print_error(f"Failed to write temporary query file: {e}")
        return None
    
    # Make sure workspace ID is just the ID, not the full resource path
    if '/' in workspace_id:
        workspace_short_id = workspace_id.split('/')[-1]
    else:
        workspace_short_id = workspace_id
    
    # Construct Azure CLI command
    subscription_param = f" --subscription {subscription_id}" if subscription_id else ""
    cmd = f"az monitor log-analytics query --workspace \"{workspace_short_id}\"{subscription_param} --analytics-query \"@{temp_query_file}\" -o json"
    
    print_info(f"Executing KQL query via Azure CLI...")
    
    try:
        # Execute the query
        result = run_command(cmd, timeout_seconds=timeout_seconds)
        
        if result:
            print_success(f"Query returned {len(result)} results")
            return result
        else:
            print_warning("Query returned no data")
            return None
    except Exception as e:
        print_error(f"Error executing KQL query: {e}")
        return None
    finally:
        # Cleanup temp file (optional)
        try:
            # Uncomment to remove temp file
            # os.remove(temp_query_file)
            pass
        except:
            pass

def query_ip_traffic(target_ip: str, time_range_hours: int = 24) -> Dict[str, Any]:
    """
    Main function to directly query IP traffic across all relevant workspaces.
    Simplified compared to the original multi-step process.
    """
    results = {}
    start_time = datetime.now()
    
    print_info(f"\n{'='*80}")
    print_info(f"Starting direct IP traffic query for: {target_ip}")
    print_info(f"Time range: {time_range_hours} hours")
    print_info(f"{'='*80}\n")
    
    # Step 1: Get subscription ID from IP
    subscription_id = get_subscription_from_ip(target_ip)
    
    # Step 2: Get workspace IDs directly (combines multiple steps from original)
    workspaces = get_workspace_for_ip(target_ip, subscription_id)
    
    if not workspaces:
        print_warning(f"No workspaces found for IP {target_ip}, cannot query flow logs")
        return results
    
    print_info(f"Found {len(workspaces)} workspace(s) to query")
    
    # Step 3: Generate KQL query once (reused for all workspaces)
    kql_query = generate_flow_query(target_ip, time_range_hours)
    
    # Step 4: Query each workspace
    all_records = []
    
    for workspace_id, sub_id in workspaces.items():
        print_info(f"\nQuerying workspace: {workspace_id}")
        
        # Use subscription from workspace discovery if available
        query_sub_id = sub_id or subscription_id
        
        # Execute query
        workspace_results = query_workspace(
            workspace_id=workspace_id,
            kql_query=kql_query,
            subscription_id=query_sub_id,
            timeout_seconds=300  # 5 minutes timeout
        )
        
        if workspace_results:
            print_success(f"Found {len(workspace_results)} records in workspace {workspace_id}")
            
            # Save per-workspace results
            results[workspace_id] = {
                'subscription_id': query_sub_id,
                'results': workspace_results
            }
            
            # Accumulate all records
            all_records.extend(workspace_results)
        else:
            print_warning(f"No results found in workspace {workspace_id}")
    
    # Save combined results if any found
    if all_records:
        output_dir = ensure_output_dir()
        timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
        
        # Save combined results to JSON
        all_results_file = os.path.join(output_dir, f"ip_traffic_{target_ip.replace('.', '_')}_{timestamp}.json")
        save_json(all_records, all_results_file)
        print_success(f"Saved combined results ({len(all_records)} records) to {all_results_file}")
        
        # Also save to Excel if pandas is available
        try:
            import pandas as pd
            df = pd.DataFrame(all_records)
            excel_file = os.path.join(output_dir, f"ip_traffic_{target_ip.replace('.', '_')}_{timestamp}.xlsx")
            df.to_excel(excel_file, index=False, engine='openpyxl')
            print_success(f"Saved combined results to Excel: {excel_file}")
        except ImportError:
            print_warning("pandas not installed, skipping Excel export")
        except Exception as e:
            print_error(f"Error saving to Excel: {e}")
    
    # Summary
    end_time = datetime.now()
    duration = (end_time - start_time).total_seconds()
    
    print_info(f"\n{'='*80}")
    if all_records:
        print_success(f"Query completed in {duration:.1f} seconds")
        print_info(f"Total flow log records found: {len(all_records)}")
        print_info(f"Records found across {len(results)} workspace(s)")
    else:
        print_warning(f"Query completed in {duration:.1f} seconds with no results")
    print_info(f"{'='*80}\n")
    
    return results
