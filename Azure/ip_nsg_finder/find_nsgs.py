"""
This module handles finding NSGs associated with a specific IP address.
Includes steps 1-2 from the original script:
1. Find network interfaces directly using target IP
2. Get NSGs associated with the subnets found via NICs
"""
import os
from typing import List, Dict, Set, Any, Optional, Tuple

from .common import (
    print_info, print_success, print_warning, 
    run_command, save_json, ensure_output_dir
)

def find_nsgs_by_ip(target_ip: str) -> Tuple[List[str], str]:
    """Find list of NSG IDs associated with an IP"""
    print_info(f"\nFinding NSGs associated with IP {target_ip}...")
    nsg_ids = []
    temp_dir = ensure_output_dir("log", "temp")
    subscription_id = None

    # 1. Find network interfaces directly using this IP
    print_info("\nStep 1: Finding network interfaces directly using this IP...")
    # Use Azure Resource Graph query for efficiency
    nic_cmd = f"az graph query -q \"Resources | where type =~ 'microsoft.network/networkinterfaces' | where properties.ipConfigurations contains '{target_ip}' | project id, name, resourceGroup, subscriptionId, subnetId = tostring(properties.ipConfigurations[0].properties.subnet.id), nsgId = tostring(properties.networkSecurityGroup.id)\" --query \"data\" -o json"

    nics = run_command(nic_cmd)
    if nics and isinstance(nics, list):  # Ensure nics is a list
        save_json(nics, os.path.join(temp_dir, f"network_interfaces_{target_ip}.json"))
        print_success(f"Found {len(nics)} network interfaces potentially associated with IP {target_ip}")

        # Extract subscription ID from the first NIC found
        if nics and 'subscriptionId' in nics[0]:
            subscription_id = nics[0]['subscriptionId']
            print_info(f"Using subscription ID: {subscription_id} for subsequent queries")

        # 1.1 Collect NSGs directly associated with NICs
        nic_subnet_ids = set()  # Use a set for unique subnet IDs
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
            subnet_id = nic.get('subnetId')  # Use the projected subnetId
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

            try:  # Add error handling for parsing
                for i, part in enumerate(parts):
                    if part.lower() == 'resourcegroups' and i+1 < len(parts):
                        resource_group = parts[i+1]
                    elif part.lower() == 'virtualnetworks' and i+1 < len(parts):
                        vnet_name = parts[i+1]
                    elif part.lower() == 'subnets' and i+1 < len(parts):
                        subnet_name = parts[i+1]
            except Exception as e:
                 print_warning(f"Could not parse subnet ID {subnet_id}: {e}")
                 continue  # Skip to next subnet ID

            if resource_group and vnet_name and subnet_name:
                print_info(f"Subnet info parsed: RG={resource_group}, VNET={vnet_name}, Subnet={subnet_name}")

                # Get detailed subnet information directly from Azure
                # Add subscription parameter if subscription_id was found
                subscription_param = f" --subscription {subscription_id}" if subscription_id else ""
                subnet_cmd = f"az network vnet subnet show --resource-group \"{resource_group}\" --vnet-name \"{vnet_name}\" --name \"{subnet_name}\"{subscription_param} -o json"
                subnet_details = run_command(subnet_cmd)

                if subnet_details:
                    save_json(subnet_details, os.path.join(temp_dir, f"subnet_{subnet_name}_{target_ip}.json"))

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

    # Save all unique NSG IDs found
    unique_nsg_ids = list(set(nsg_ids))  # Ensure uniqueness
    if unique_nsg_ids:
        save_json(unique_nsg_ids, os.path.join(temp_dir, f"nsg_ids_found_{target_ip}.json"))
        print_success(f"\nTotal unique NSGs potentially related to IP {target_ip}: {len(unique_nsg_ids)}")
        for i, nsg_id in enumerate(unique_nsg_ids):
            print(f"  {i+1}. {nsg_id}")
    else:
        print_warning(f"\nNo NSGs found potentially related to IP {target_ip}")

    # Return both NSG IDs and subscription_id
    return unique_nsg_ids, subscription_id
