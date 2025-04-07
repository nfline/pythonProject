"""
This module handles NSG flow logs configuration and Log Analytics workspace discovery.
Includes steps 4-5 from the original script:
4. Get flow logs configuration for NSGs
5. Extract Log Analytics workspace information
"""
import os
from typing import List, Dict, Any, Optional

from .common import (
    print_info, print_success, print_warning, 
    run_command, save_json, ensure_output_dir
)

def get_nsg_flow_logs_config(nsg_ids: List[str], target_ip: str, subscription_id: Optional[str] = None) -> Dict[str, Dict]:
    """Get flow logs configuration for NSGs"""
    print_info("\nStep 4: Getting NSG flow logs configuration...")
    output_dir = ensure_output_dir()
    flow_logs_config = {}

    for nsg_id in nsg_ids:
        # Extract resource group and NSG name from NSG ID
        parts = nsg_id.split('/')
        resource_group = None
        nsg_name = None

        try:  # Add error handling
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
        # Add subscription parameter if subscription_id was found
        subscription_param = f" --subscription {subscription_id}" if subscription_id else ""
        # Query includes workspace ID directly if available
        flow_logs_cmd = f"az graph query -q \"Resources | where type =~ 'Microsoft.Network/networkWatchers/flowLogs' | where properties.targetResourceId =~ '{nsg_id}' | project id, name, resourceGroup, flowLogResourceId=id, workspaceId=properties.flowAnalyticsConfiguration.networkWatcherFlowAnalyticsConfiguration.workspaceId, enabled=properties.enabled, retentionDays=properties.retentionPolicy.days\"{subscription_param} --query \"data\" -o json"

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
    workspace_ids = {}  # Maps NSG ID to Workspace ID
    output_dir = ensure_output_dir()

    for nsg_id, config in flow_logs_config.items():
        nsg_name = nsg_id.split('/')[-1]  # For logging
        workspace_id = None

        # Extract workspace ID directly from the Graph query result
        if isinstance(config, dict):
            workspace_id = config.get('workspaceId')

        if workspace_id:
            # Validate workspace ID format - accept full Resource ID or just GUID
            is_guid_format = len(workspace_id) == 36 and workspace_id.count('-') == 4
            is_full_id_format = '/subscriptions/' in workspace_id and '/workspaces/' in workspace_id

            if is_full_id_format or is_guid_format:
                workspace_ids[nsg_id] = workspace_id  # Store whatever format we received
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
