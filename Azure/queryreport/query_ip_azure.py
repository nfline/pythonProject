#!/usr/bin/env python3
"""
query_ip_azure.py - Query Azure network traffic logs by IP address
Usage: python query_ip_azure.py <IP_address> [--days <number>]

This script finds resources associated with the specified IP address,
identifies relevant NSGs and their flow logs, and queries relevant
Log Analytics workspaces for network traffic data.

Examples:
  python query_ip_azure.py 10.0.0.1
  python query_ip_azure.py 192.168.1.100 --days 7
"""

import os
import sys
import json
import time
import datetime
import argparse
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple, Union

# Azure imports
try:
    from azure.identity import DefaultAzureCredential, AzureCliCredential
    from azure.mgmt.resource import ResourceManagementClient
    from azure.mgmt.network import NetworkManagementClient
    from azure.mgmt.monitor import MonitorManagementClient
    from azure.mgmt.loganalytics import LogAnalyticsManagementClient
    from azure.core.exceptions import ClientAuthenticationError, HttpResponseError
except ImportError:
    print("Error: Required Azure packages are missing.")
    print("Please install them using: pip install azure-identity azure-mgmt-resource azure-mgmt-network azure-mgmt-monitor azure-mgmt-loganalytics")
    sys.exit(1)

# ANSI colors for terminal output
class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    RESET = '\033[0m'
    BOLD = '\033[1m'

def print_color(text: str, color: str, bold: bool = False) -> None:
    """Print colored text to the console."""
    if bold:
        print(f"{Colors.BOLD}{color}{text}{Colors.RESET}")
    else:
        print(f"{color}{text}{Colors.RESET}")

def print_info(text: str) -> None:
    """Print informational message."""
    print_color(text, Colors.BLUE)

def print_success(text: str) -> None:
    """Print success message."""
    print_color(text, Colors.GREEN)

def print_warning(text: str) -> None:
    """Print warning message."""
    print_color(text, Colors.YELLOW)

def print_error(text: str) -> None:
    """Print error message."""
    print_color(text, Colors.RED)

def save_json(data: Union[List, Dict], file_path: str) -> None:
    """Save data to JSON file."""
    with open(file_path, 'w') as f:
        json.dump(data, f, indent=2)
    print(f"Saved data to {file_path}")

def save_csv(data: List[Dict], file_path: str, headers: List[str]) -> None:
    """Save data to CSV file."""
    import csv
    with open(file_path, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(headers)
        for item in data:
            row = [item.get(h.split(':')[0], '') for h in headers]
            writer.writerow(row)
    print(f"Saved CSV to {file_path}")

class AzureIPTrafficAnalyzer:
    """Azure IP Traffic Analyzer class for querying network traffic by IP."""
    
    def __init__(self, target_ip: str, days_back: int = 30):
        """
        Initialize the analyzer with target IP and time range.
        
        Args:
            target_ip: The IP address to analyze
            days_back: Number of days to look back for traffic data
        """
        self.target_ip = target_ip
        self.days_back = days_back
        
        # Calculate time range
        end_date = datetime.datetime.utcnow()
        start_date = end_date - datetime.timedelta(days=days_back)
        self.start_date = start_date.strftime('%Y-%m-%dT%H:%M:%SZ')
        self.end_date = end_date.strftime('%Y-%m-%dT%H:%M:%SZ')
        
        # Create output directory
        date_tag = time.strftime('%Y%m%d%H%M%S')
        self.output_dir = f"ip_traffic_{target_ip.replace('.', '_')}_{date_tag}"
        os.makedirs(self.output_dir, exist_ok=True)
        
        # Initialize Azure clients
        self.credential = None
        self.subscription_id = None
        self.resource_client = None
        self.network_client = None
        self.monitor_client = None
        self.loganalytics_client = None
        
        # Results containers
        self.associated_resources = []
        self.related_nsg_rules = []
        self.flow_logs = []
        self.target_workspaces = []
        self.all_network_traffic = []
        self.subnet_nsg_ids = []
        
        print_info("=" * 60)
        print_success("Azure IP Traffic Analyzer (Python)")
        print_info("=" * 60)
        print(f"Target IP: {Colors.YELLOW}{self.target_ip}{Colors.RESET}")
        print(f"Time Range: {Colors.YELLOW}{self.start_date}{Colors.RESET} to {Colors.YELLOW}{self.end_date}{Colors.RESET}")
        print(f"Output Directory: {Colors.YELLOW}{self.output_dir}{Colors.RESET}")
        print_info("=" * 60)

    def login_to_azure(self) -> bool:
        """
        Authenticate with Azure and retrieve current subscription.
        
        Returns:
            bool: True if authentication successful, False otherwise
        """
        print_info("\n[1/5] Checking Azure login status...")
        
        try:
            # Use subprocess to call az commands directly, similar to the shell script
            import subprocess
            import json
            import shutil
            import os
            
            # First check if az command is available
            az_path = shutil.which("az")
            if not az_path:
                print_error("Azure CLI (az command) not found in PATH")
                print("Please install Azure CLI by following these steps:")
                print("1. Visit: https://docs.microsoft.com/en-us/cli/azure/install-azure-cli")
                print("2. Run the installer for Windows")
                print("3. Restart your terminal/command prompt")
                print("4. Try running 'az --version' to verify installation")
                return False
                
            print(f"Found Azure CLI at: {az_path}")
            
            # Check if already logged in
            try:
                # Run 'az account show' to check login status (using shell=True for Windows paths with spaces)
                result = subprocess.run(
                    "az account show --query id -o tsv",
                    shell=True,
                    capture_output=True,
                    text=True,
                    check=False
                )
                
                if result.returncode == 0 and result.stdout.strip():
                    self.subscription_id = result.stdout.strip()
                    print_success(f"Already logged in to Azure")
                    
                    # Get tenant ID
                    tenant_result = subprocess.run(
                        "az account show --query tenantId -o tsv",
                        shell=True,
                        capture_output=True,
                        text=True,
                        check=False
                    )
                    tenant_id = tenant_result.stdout.strip() if tenant_result.returncode == 0 else "Unknown"
                    
                    print(f"Current Subscription: {Colors.YELLOW}{self.subscription_id}{Colors.RESET}")
                    print(f"Current Tenant: {Colors.YELLOW}{tenant_id}{Colors.RESET}")
                else:
                    print("Not logged in. Attempting to login to Azure...")
                    # Run 'az login'
                    login_result = subprocess.run(
                        "az login",
                        shell=True,
                        capture_output=False,  # Let the login process show its own output for browser opening
                        text=True,
                        check=False
                    )
                    
                    if login_result.returncode != 0:
                        print_error(f"Login failed")
                        return False
                    
                    # Get subscription ID
                    result = subprocess.run(
                        "az account show --query id -o tsv",
                        shell=True,
                        capture_output=True,
                        text=True,
                        check=False
                    )
                    
                    if result.returncode == 0 and result.stdout.strip():
                        self.subscription_id = result.stdout.strip()
                        
                        # Get tenant ID
                        tenant_result = subprocess.run(
                            "az account show --query tenantId -o tsv",
                            shell=True,
                            capture_output=True,
                            text=True,
                            check=False
                        )
                        tenant_id = tenant_result.stdout.strip() if tenant_result.returncode == 0 else "Unknown"
                        
                        print_success(f"Successfully logged in to Azure")
                        print(f"Current Subscription: {Colors.YELLOW}{self.subscription_id}{Colors.RESET}")
                        print(f"Current Tenant: {Colors.YELLOW}{tenant_id}{Colors.RESET}")
                    else:
                        print_error("Failed to get subscription ID after login")
                        return False
                
                # Initialize Azure clients using AzureCliCredential
                # This will directly use the CLI's login session
                self.credential = AzureCliCredential()
                self.resource_client = ResourceManagementClient(self.credential, self.subscription_id)
                self.network_client = NetworkManagementClient(self.credential, self.subscription_id)
                self.monitor_client = MonitorManagementClient(self.credential, self.subscription_id)
                self.loganalytics_client = LogAnalyticsManagementClient(self.credential, self.subscription_id)
                
                return True
                
            except subprocess.SubprocessError as e:
                print_error(f"Error executing Azure CLI command: {str(e)}")
                return False
                
        except Exception as e:
            print_error(f"Unexpected error during authentication: {str(e)}")
            import traceback
            traceback.print_exc()
            return False

    def find_resources_by_ip(self) -> None:
        """Find Azure resources associated with the target IP address and determine related NSG flow logs."""
        print_info(f"\n[2/5] Finding resources associated with IP {self.target_ip}...")
        
        try:
            # Check if credential is properly set up
            if self.credential is None:
                print_error("Azure credential is not initialized. Please run login_to_azure() first.")
                return
                
            # Use Azure Resource Graph to query for NICs with this IP
            try:
                from azure.mgmt.resourcegraph import ResourceGraphClient
                from azure.mgmt.resourcegraph.models import QueryRequest
                
                print_info("Creating Resource Graph client...")
                graph_client = ResourceGraphClient(self.credential)
                
                # 1. DIRECTLY QUERY NETWORK INTERFACES WITH THIS IP
                print_info(f"Querying for network interfaces with IP {self.target_ip}...")
                query = f"""
                Resources
                | where type =~ 'microsoft.network/networkinterfaces'
                | where properties.ipConfigurations[0].properties.privateIPAddress =~ '{self.target_ip}'
                | project id, name, resourceGroup, subscriptionId, location, 
                         vnetId = tostring(properties.ipConfigurations[0].properties.subnet.id),
                         subnetName = tostring(split(properties.ipConfigurations[0].properties.subnet.id, '/')[-1]),
                         nsgId = tostring(properties.networkSecurityGroup.id)
                """
                
                request = QueryRequest(query=query, subscriptions=[self.subscription_id])
                response = graph_client.resources(request)
                
                if response.data:
                    self.associated_resources = response.data
                    save_json(self.associated_resources, os.path.join(self.output_dir, "associated_resources.json"))
                    print_success(f"Found {len(self.associated_resources)} resources with IP {self.target_ip}")
                    
                    # 2. EXTRACT VNET AND SUBNET INFO
                    vnet_ids = []
                    subnet_ids = []
                    nsg_ids = []
                    
                    for nic in self.associated_resources:
                        vnet_id = nic.get('vnetId')
                        if vnet_id:
                            # Extract VNET ID from subnet ID (format: /subscriptions/{sub}/resourceGroups/{rg}/providers/Microsoft.Network/virtualNetworks/{vnet}/subnets/{subnet})
                            vnet_parts = vnet_id.split('/')
                            if len(vnet_parts) >= 9:
                                # Reconstruct VNET ID
                                v_id = '/'.join(vnet_parts[:-2])
                                if v_id and v_id not in vnet_ids:
                                    vnet_ids.append(v_id)
                                
                                # Save subnet ID
                                if vnet_id not in subnet_ids:
                                    subnet_ids.append(vnet_id)
                        
                        # Collect NSGs directly associated with NICs
                        nsg_id = nic.get('nsgId')
                        if nsg_id and nsg_id not in nsg_ids:
                            nsg_ids.append(nsg_id)
                    
                    print_success(f"Found {len(vnet_ids)} related virtual networks")
                    print_success(f"Found {len(subnet_ids)} related subnets")
                    
                    # 3. QUERY SUBNETS FOR NSG INFORMATION
                    if subnet_ids:
                        print_info("Querying subnet network security groups...")
                        
                        # Format subnet IDs for query
                        subnet_id_list = ",".join([f"'{s}'" for s in subnet_ids])
                        
                        subnet_query = f"""
                        Resources
                        | where type =~ 'microsoft.network/virtualnetworks'
                        | mv-expand subnet=properties.subnets
                        | where subnet.id in~ ({subnet_id_list})
                        | project subnetId = subnet.id,
                                  subnetName = subnet.name,
                                  nsgId = tostring(subnet.properties.networkSecurityGroup.id)
                        """
                        
                        try:
                            subnet_request = QueryRequest(query=subnet_query, subscriptions=[self.subscription_id])
                            subnet_response = graph_client.resources(subnet_request)
                            
                            if subnet_response.data:
                                for subnet in subnet_response.data:
                                    subnet_nsg = subnet.get('nsgId')
                                    if subnet_nsg and subnet_nsg not in nsg_ids:
                                        nsg_ids.append(subnet_nsg)
                        except Exception as subnet_error:
                            print_warning(f"Error querying subnet NSGs: {str(subnet_error)}")
                    
                    # Save all related NSG IDs
                    self.subnet_nsg_ids = nsg_ids
                    save_json(nsg_ids, os.path.join(self.output_dir, "related_nsg_ids.json"))
                    print_success(f"Found {len(nsg_ids)} associated network security groups")
                    
                    # 4. Directly proceed to find flow logs for the collected NSGs
                    if nsg_ids:
                        self.find_flow_logs()
                    else:
                        print_warning("No associated NSGs found, cannot query flow logs")
                else:
                    # If no network interfaces found, try to find subnets containing this IP
                    print_warning(f"No resources with IP {self.target_ip} found, trying to find subnets containing this IP...")
                    self._find_subnets_containing_ip(graph_client)
            except ImportError:
                print_error("Unable to import azure.mgmt.resourcegraph. Please install it using: pip install azure-mgmt-resourcegraph")
                return
            except Exception as query_error:
                print_error(f"Error querying resources: {str(query_error)}")
                # Try alternative method using Azure CLI
                self._fallback_to_azure_cli()
        except Exception as e:
            print_error(f"Error finding resources: {str(e)}")
            import traceback
            traceback.print_exc()
    
    def _find_subnets_containing_ip(self, graph_client=None):
        """Helper method to find subnets containing the target IP."""
        print_info(f"Searching for subnets that contain IP {self.target_ip}...")
        
        # Parse the IP address to determine subnet range
        ip_parts = self.target_ip.split('.')
        if len(ip_parts) != 4:
            print_error(f"Invalid IP address format: {self.target_ip}")
            return False
            
        # Convert IP string to integer for subnet calculations
        try:
            ip_int = (int(ip_parts[0]) << 24) + (int(ip_parts[1]) << 16) + (int(ip_parts[2]) << 8) + int(ip_parts[3])
        except ValueError:
            print_error(f"Invalid IP address components: {self.target_ip}")
            return False
        
        # Create Resource Graph client if not provided
        if graph_client is None:
            try:
                from azure.mgmt.resourcegraph import ResourceGraphClient
                from azure.mgmt.resourcegraph.models import QueryRequest
                graph_client = ResourceGraphClient(self.credential)
            except (ImportError, Exception) as e:
                print_error(f"Error creating Resource Graph client: {str(e)}")
                return False
        
        # Query virtual networks and their subnets
        try:
            query = """
            Resources
            | where type =~ 'microsoft.network/virtualnetworks'
            | mv-expand subnet=properties.subnets
            | project vnetName=name, vnetId=id, subnetName=subnet.name, 
                     subnetPrefix=subnet.properties.addressPrefix,
                     subnetId=subnet.id, 
                     nsgId=subnet.properties.networkSecurityGroup.id,
                     resourceGroup, subscriptionId, location
            """
            
            request = QueryRequest(query=query, subscriptions=[self.subscription_id])
            response = graph_client.resources(request)
            
            # Function to check if IP is in subnet
            def ip_in_subnet(ip_addr, subnet_prefix):
                try:
                    subnet_addr, subnet_mask = subnet_prefix.split('/')
                    subnet_mask = int(subnet_mask)
                    
                    subnet_parts = subnet_addr.split('.')
                    if len(subnet_parts) != 4:
                        return False
                        
                    subnet_int = (int(subnet_parts[0]) << 24) + (int(subnet_parts[1]) << 16) + \
                                 (int(subnet_parts[2]) << 8) + int(subnet_parts[3])
                                 
                    mask_int = (0xFFFFFFFF << (32 - subnet_mask)) & 0xFFFFFFFF
                    
                    return (ip_int & mask_int) == (subnet_int & mask_int)
                except:
                    return False
            
            # Process subnets
            matching_subnets = []
            nsg_ids = []
            
            if response.data:
                all_subnets = response.data
                
                # Find subnets that contain this IP
                for subnet in all_subnets:
                    subnet_prefix = subnet.get('subnetPrefix')
                    
                    # Handle case where subnet prefix is an array
                    if isinstance(subnet_prefix, list):
                        for prefix in subnet_prefix:
                            if ip_in_subnet(self.target_ip, prefix):
                                matching_subnets.append(subnet)
                                break
                    else:
                        if subnet_prefix and ip_in_subnet(self.target_ip, subnet_prefix):
                            matching_subnets.append(subnet)
                
                # Save matching subnets
                if matching_subnets:
                    save_json(matching_subnets, os.path.join(self.output_dir, "matching_subnets.json"))
                    print_success(f"Found {len(matching_subnets)} subnets that contain IP {self.target_ip}")
                    
                    # Extract NSG IDs from matching subnets
                    for subnet in matching_subnets:
                        nsg_id = subnet.get('nsgId')
                        if nsg_id and nsg_id not in nsg_ids:
                            nsg_ids.append(nsg_id)
                    
                    if nsg_ids:
                        print_success(f"Found {len(nsg_ids)} NSGs associated with subnets containing this IP")
                        # Store for later use in find_flow_logs
                        self.subnet_nsg_ids = nsg_ids
                        self.find_flow_logs()
                        return True
                    else:
                        print_warning("No NSGs found for matching subnets")
                else:
                    print_warning(f"No subnets found that contain IP {self.target_ip}")
            else:
                print_warning("No virtual networks found in the subscription")
            
            return False
        except Exception as e:
            print_error(f"Error finding subnets: {str(e)}")
            return False
    
    def _fallback_to_azure_cli(self):
        """Fallback method using Azure CLI when Resource Graph queries fail."""
        print_info("Attempting to use Azure CLI directly...")
        import subprocess
        import json
        
        # 1. Query network interfaces with this IP
        print_info(f"Querying for network interfaces with IP {self.target_ip} using Azure CLI...")
        cmd = f"az graph query -q \"Resources | where type =~ 'microsoft.network/networkinterfaces' | where properties.ipConfigurations[0].properties.privateIPAddress =~ '{self.target_ip}' | project id, name, resourceGroup, subscriptionId, location, vnetId = tostring(properties.ipConfigurations[0].properties.subnet.id), nsgId = tostring(properties.networkSecurityGroup.id)\" --query \"data\" -o json"
        
        try:
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, check=False)
            if result.returncode == 0 and result.stdout.strip():
                self.associated_resources = json.loads(result.stdout)
                save_json(self.associated_resources, os.path.join(self.output_dir, "associated_resources.json"))
                print_success(f"Found {len(self.associated_resources)} resources with IP {self.target_ip} (using CLI)")
                
                # Extract NSG IDs
                nsg_ids = []
                for resource in self.associated_resources:
                    nsg_id = resource.get('nsgId')
                    if nsg_id and nsg_id not in nsg_ids:
                        nsg_ids.append(nsg_id)
                
                if nsg_ids:
                    self.subnet_nsg_ids = nsg_ids
                    print_success(f"Found {len(nsg_ids)} associated NSGs")
                    self.find_flow_logs()
                    return True
                else:
                    # If no NSGs found directly with NIC, try to find subnets
                    print_warning("No NSGs directly associated with network interface, trying to find subnet NSGs...")
                    self._find_subnets_cli()
            else:
                print_warning(f"No resources with IP {self.target_ip} found using Azure CLI")
                self._find_subnets_cli()
                
        except Exception as cli_error:
            print_error(f"Error using Azure CLI: {str(cli_error)}")
            return False
    
    def _find_subnets_cli(self):
        """Find subnets containing the target IP using Azure CLI."""
        print_info(f"Finding subnets containing IP {self.target_ip} using Azure CLI...")
        import subprocess
        import json
        
        try:
            # First get all VNETs
            cmd_vnets = "az graph query -q \"Resources | where type =~ 'microsoft.network/virtualnetworks' | project id, name, resourceGroup, properties.subnets\" --query \"data\" -o json"
            result = subprocess.run(cmd_vnets, shell=True, capture_output=True, text=True, check=False)
            
            if result.returncode == 0 and result.stdout.strip():
                vnets = json.loads(result.stdout)
                
                # Parse IP to components for subnet check
                ip_parts = self.target_ip.split('.')
                if len(ip_parts) != 4:
                    print_error(f"Invalid IP address format: {self.target_ip}")
                    return False
                
                ip_int = (int(ip_parts[0]) << 24) + (int(ip_parts[1]) << 16) + (int(ip_parts[2]) << 8) + int(ip_parts[3])
                
                # Function to check if IP is in subnet
                def ip_in_subnet(ip_addr, subnet_prefix):
                    try:
                        subnet_addr, subnet_mask = subnet_prefix.split('/')
                        subnet_mask = int(subnet_mask)
                        
                        subnet_parts = subnet_addr.split('.')
                        if len(subnet_parts) != 4:
                            return False
                            
                        subnet_int = (int(subnet_parts[0]) << 24) + (int(subnet_parts[1]) << 16) + \
                                     (int(subnet_parts[2]) << 8) + int(subnet_parts[3])
                                     
                        mask_int = (0xFFFFFFFF << (32 - subnet_mask)) & 0xFFFFFFFF
                        
                        return (ip_int & mask_int) == (subnet_int & mask_int)
                    except:
                        return False
                
                matching_subnets = []
                nsg_ids = []
                
                for vnet in vnets:
                    subnets = vnet.get('properties.subnets', [])
                    for subnet in subnets:
                        prefix = subnet.get('properties', {}).get('addressPrefix')
                        if prefix and ip_in_subnet(self.target_ip, prefix):
                            matching_subnets.append({
                                'vnetName': vnet.get('name'),
                                'vnetId': vnet.get('id'),
                                'subnetName': subnet.get('name'),
                                'subnetPrefix': prefix,
                                'subnetId': subnet.get('id'),
                                'nsgId': subnet.get('properties', {}).get('networkSecurityGroup', {}).get('id')
                            })
                            
                            nsg_id = subnet.get('properties', {}).get('networkSecurityGroup', {}).get('id')
                            if nsg_id and nsg_id not in nsg_ids:
                                nsg_ids.append(nsg_id)
                
                if matching_subnets:
                    save_json(matching_subnets, os.path.join(self.output_dir, "matching_subnets.json"))
                    print_success(f"Found {len(matching_subnets)} subnets containing IP {self.target_ip} (using CLI)")
                    
                    if nsg_ids:
                        self.subnet_nsg_ids = nsg_ids
                        print_success(f"Found {len(nsg_ids)} NSGs associated with subnets (using CLI)")
                        self.find_flow_logs()
                        return True
                    else:
                        print_warning("No NSGs found for matching subnets")
                else:
                    print_warning(f"No subnets found containing IP {self.target_ip} (using CLI)")
            else:
                print_warning("Failed to retrieve virtual networks (using CLI)")
                
            return False
        except Exception as e:
            print_error(f"Error finding subnets using CLI: {str(e)}")
            return False

    def find_flow_logs(self) -> None:
        """Find NSG flow logs for relevant NSGs."""
        print_info(f"\n[3/5] Finding NSG flow logs...")
        
        # Collect NSG IDs from both direct associations and related rules
        nsg_ids = []
        
        # Add NSGs from direct resource associations
        for resource in self.associated_resources:
            nsg_id = resource.get('nsgId')
            if nsg_id and nsg_id not in nsg_ids:
                nsg_ids.append(nsg_id)
                
        # Add NSGs from related rules
        for nsg in self.related_nsg_rules:
            nsg_id = nsg.get('id')
            if nsg_id and nsg_id not in nsg_ids:
                nsg_ids.append(nsg_id)
                
        # Add NSGs from subnets
        for nsg_id in self.subnet_nsg_ids:
            if nsg_id not in nsg_ids:
                nsg_ids.append(nsg_id)
                
        if not nsg_ids:
            print_warning("No related NSGs found to check for flow logs")
            return
            
        print_info(f"Checking flow logs for {len(nsg_ids)} NSGs...")
        
        try:
            # Find flow logs for each NSG
            for nsg_id in nsg_ids:
                # Extract resource group from NSG ID
                parts = nsg_id.split('/')
                if len(parts) < 5:
                    continue
                    
                resource_group = None
                for i, part in enumerate(parts):
                    if part.lower() == 'resourcegroups' and i+1 < len(parts):
                        resource_group = parts[i+1]
                        break
                        
                if not resource_group:
                    continue
                    
                # Get NSG name from ID
                nsg_name = parts[-1] if parts else None
                if not nsg_name:
                    continue
                    
                # Query for flow logs targeting this NSG
                try:
                    # Use Azure Resource Graph for more efficient querying
                    from azure.mgmt.resourcegraph import ResourceGraphClient
                    from azure.mgmt.resourcegraph.models import QueryRequest
                    
                    graph_client = ResourceGraphClient(self.credential)
                    
                    query = f"""
                    Resources
                    | where type =~ 'microsoft.network/networkwatchers/flowlogs'
                    | where properties.targetResourceId =~ '{nsg_id}'
                    | project id, name, resourceGroup, location, enabled=properties.enabled,
                              retentionPolicy=properties.retentionPolicy,
                              storageId=properties.storageId,
                              workspaceId=properties.flowAnalyticsConfiguration.networkWatcherFlowAnalyticsConfiguration.workspaceId
                    """
                    
                    request = QueryRequest(query=query, subscriptions=[self.subscription_id])
                    response = graph_client.resources(request)
                    
                    if response.data:
                        for flow_log in response.data:
                            self.flow_logs.append(flow_log)
                            
                            # Extract workspace ID if present
                            workspace_id = flow_log.get('workspaceId')
                            if workspace_id and workspace_id not in [w.get('id') for w in self.target_workspaces]:
                                # Get workspace details
                                workspace_parts = workspace_id.split('/')
                                if len(workspace_parts) < 9:
                                    continue
                                    
                                workspace_rg = None
                                for i, part in enumerate(workspace_parts):
                                    if part.lower() == 'resourcegroups' and i+1 < len(workspace_parts):
                                        workspace_rg = workspace_parts[i+1]
                                        break
                                        
                                workspace_name = workspace_parts[-1] if workspace_parts else None
                                
                                if workspace_rg and workspace_name:
                                    try:
                                        workspace = self.loganalytics_client.workspaces.get(workspace_rg, workspace_name)
                                        if workspace:
                                            # Add to target workspaces
                                            self.target_workspaces.append({
                                                'id': workspace_id,
                                                'name': workspace_name,
                                                'resourceGroup': workspace_rg,
                                                'customerId': workspace.customer_id
                                            })
                                    except HttpResponseError as e:
                                        print_warning(f"Could not access workspace {workspace_name}: {str(e)}")
                                    except Exception as e:
                                        print_warning(f"Error retrieving workspace details: {str(e)}")
                
                except Exception as e:
                    print_warning(f"Error querying flow logs for NSG {nsg_name}: {str(e)}")
            
            # Save flow logs data
            if self.flow_logs:
                save_json(self.flow_logs, os.path.join(self.output_dir, "nsg_flow_logs.json"))
                print_success(f"Found {len(self.flow_logs)} NSG flow logs")
                
                # Generate CSV for flow logs
                if self.flow_logs:
                    headers = ["id", "name", "resourceGroup", "location", "enabled", "workspaceId"]
                    save_csv(self.flow_logs, 
                             os.path.join(self.output_dir, "nsg_flow_logs.csv"),
                             headers)
            else:
                print_warning("No flow logs found for the relevant NSGs")
                
            # Save target workspaces
            if self.target_workspaces:
                save_json(self.target_workspaces, os.path.join(self.output_dir, "target_workspaces.json"))
                print_success(f"Found {len(self.target_workspaces)} target Log Analytics workspaces")
                
                headers = ["id", "name", "resourceGroup", "customerId"]
                save_csv(self.target_workspaces,
                         os.path.join(self.output_dir, "target_workspaces.csv"),
                         headers)
            else:
                print_warning("No Log Analytics workspaces found for the flow logs")
                
        except Exception as e:
            print_error(f"Error finding flow logs: {str(e)}")
            
    def query_traffic_data(self) -> None:
        """Query Log Analytics workspaces for traffic data related to the IP."""
        print_info(f"\n[4/5] Querying traffic data from Log Analytics workspaces...")
        
        if not self.target_workspaces:
            print_warning("No target workspaces to query")
            return
            
        print_info(f"Querying {len(self.target_workspaces)} workspaces for traffic data...")
        
        # Get SDK package for log analytics queries
        try:
            from azure.monitor.query import LogsQueryClient
            from azure.monitor.query import LogsQueryStatus
            from azure.core.exceptions import HttpResponseError
        except ImportError:
            print_error("Error: Required Azure package azure-monitor-query is missing.")
            print("Please install it using: pip install azure-monitor-query")
            return
            
        # Set up logs query client
        logs_client = LogsQueryClient(self.credential)
        
        try:
            all_traffic_records = []
            
            # Query each workspace for traffic data
            for workspace in self.target_workspaces:
                workspace_id = workspace.get('id')
                workspace_name = workspace.get('name')
                customer_id = workspace.get('customerId')
                
                if not customer_id:
                    print_warning(f"Missing customer ID for workspace {workspace_name}, skipping")
                    continue
                
                print_info(f"Querying workspace: {workspace_name}")
                
                # KQL query for traffic data
                query = f"""
                AzureNetworkAnalytics_CL
                | where TimeGenerated >= datetime('{self.start_date}') and TimeGenerated <= datetime('{self.end_date}')
                | where SrcIP_s == '{self.target_ip}' or DestIP_s == '{self.target_ip}'
                | project TimeGenerated, FlowStartTime_t, FlowEndTime_t, FlowType_s, 
                          SrcIP_s, SrcPort_d, DestIP_s, DestPort_d, 
                          L4Protocol_s, L7Protocol_s, NSGRule_s, NSGList_s,
                          FlowDirection_s, AllowedInFlows_d, AllowedOutFlows_d,
                          DeniedInFlows_d, DeniedOutFlows_d
                | order by TimeGenerated desc
                """
                
                try:
                    # Execute query
                    response = logs_client.query_workspace(
                        workspace_id=customer_id,
                        query=query,
                        timespan=(self.start_date, self.end_date)
                    )
                    
                    # Process results
                    if response.status == LogsQueryStatus.SUCCESS:
                        records = []
                        if response.tables:
                            for table in response.tables:
                                for row in table.rows:
                                    record = {}
                                    for col_idx, column in enumerate(table.columns):
                                        record[column.name] = row[col_idx]
                                    records.append(record)
                                    
                        # Add workspace details to each record
                        for record in records:
                            record['WorkspaceName'] = workspace_name
                            record['WorkspaceID'] = customer_id
                            
                        # Add to overall results
                        all_traffic_records.extend(records)
                        
                        print_success(f"Found {len(records)} traffic records in workspace {workspace_name}")
                    else:
                        print_warning(f"Query failed for workspace {workspace_name}: {response.status}")
                        
                except HttpResponseError as e:
                    print_warning(f"Error querying workspace {workspace_name}: {str(e)}")
                except Exception as e:
                    print_warning(f"Unexpected error querying workspace {workspace_name}: {str(e)}")
            
            # Save all traffic data
            self.all_network_traffic = all_traffic_records
            
            if self.all_network_traffic:
                save_json(self.all_network_traffic, os.path.join(self.output_dir, "network_traffic.json"))
                print_success(f"Found total of {len(self.all_network_traffic)} traffic records across all workspaces")
                
                # Generate CSV for traffic data
                if self.all_network_traffic and len(self.all_network_traffic) > 0:
                    # Use keys from first record to build headers
                    first_record = self.all_network_traffic[0]
                    headers = list(first_record.keys())
                    
                    save_csv(self.all_network_traffic,
                             os.path.join(self.output_dir, "network_traffic.csv"),
                             headers)
            else:
                print_warning(f"No traffic data found for IP {self.target_ip} in the specified time range")
                
        except Exception as e:
            print_error(f"Error querying traffic data: {str(e)}")

    def generate_report(self) -> None:
        """Generate a summary report of findings."""
        print_info(f"\n[5/5] Generating summary report...")
        
        # Create report file
        report_file = os.path.join(self.output_dir, "summary_report.md")
        
        with open(report_file, 'w') as f:
            f.write(f"# Azure IP Traffic Analysis Report\n\n")
            f.write(f"## Summary\n\n")
            f.write(f"- **Target IP:** {self.target_ip}\n")
            f.write(f"- **Time Range:** {self.start_date} to {self.end_date}\n")
            f.write(f"- **Report Generated:** {datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}\n\n")
            
            f.write(f"## Associated Resources\n\n")
            if self.associated_resources:
                f.write(f"Found {len(self.associated_resources)} resources with IP {self.target_ip}\n\n")
                f.write("| Resource Name | Resource Group | Location | NSG ID |\n")
                f.write("|--------------|---------------|----------|--------|\n")
                
                for resource in self.associated_resources:
                    name = resource.get('name', 'N/A')
                    rg = resource.get('resourceGroup', 'N/A')
                    location = resource.get('location', 'N/A')
                    nsg_id = resource.get('nsgId', 'N/A')
                    nsg_name = nsg_id.split('/')[-1] if nsg_id else 'N/A'
                    
                    f.write(f"| {name} | {rg} | {location} | {nsg_name} |\n")
            else:
                f.write("No resources directly associated with this IP address were found.\n\n")
                
            f.write(f"\n## Related NSG Rules\n\n")
            if self.related_nsg_rules:
                f.write(f"Found {len(self.related_nsg_rules)} NSGs with rules referencing IP {self.target_ip}\n\n")
                f.write("| NSG Name | Resource Group | Location |\n")
                f.write("|----------|---------------|----------|\n")
                
                for nsg in self.related_nsg_rules:
                    name = nsg.get('name', 'N/A')
                    rg = nsg.get('resourceGroup', 'N/A')
                    location = nsg.get('location', 'N/A')
                    
                    f.write(f"| {name} | {rg} | {location} |\n")
            else:
                f.write("No NSGs with rules referencing this IP address were found.\n\n")
                
            f.write(f"\n## NSG Flow Logs\n\n")
            if self.flow_logs:
                f.write(f"Found {len(self.flow_logs)} flow logs for relevant NSGs\n\n")
                f.write("| Flow Log Name | Resource Group | Enabled | Workspace |\n")
                f.write("|--------------|---------------|---------|----------|\n")
                
                for flow_log in self.flow_logs:
                    name = flow_log.get('name', 'N/A')
                    rg = flow_log.get('resourceGroup', 'N/A')
                    enabled = flow_log.get('enabled', 'N/A')
                    workspace_id = flow_log.get('workspaceId', 'N/A')
                    workspace_name = workspace_id.split('/')[-1] if workspace_id else 'N/A'
                    
                    f.write(f"| {name} | {rg} | {enabled} | {workspace_name} |\n")
            else:
                f.write("No flow logs were found for the relevant NSGs.\n\n")
                
            f.write(f"\n## Traffic Data\n\n")
            if self.all_network_traffic:
                f.write(f"Found {len(self.all_network_traffic)} traffic records across all workspaces\n\n")
                
                # Group by source and destination
                sources = {}
                destinations = {}
                protocols = {}
                allowed = 0
                denied = 0
                
                for record in self.all_network_traffic:
                    # Count sources
                    src_ip = record.get('SrcIP_s')
                    if src_ip:
                        sources[src_ip] = sources.get(src_ip, 0) + 1
                        
                    # Count destinations
                    dst_ip = record.get('DestIP_s')
                    if dst_ip:
                        destinations[dst_ip] = destinations.get(dst_ip, 0) + 1
                        
                    # Count protocols
                    protocol = record.get('L4Protocol_s')
                    if protocol:
                        protocols[protocol] = protocols.get(protocol, 0) + 1
                        
                    # Count allowed vs denied
                    flow_type = record.get('FlowType_s', '').lower()
                    if 'allowed' in flow_type:
                        allowed += 1
                    elif 'denied' in flow_type:
                        denied += 1
                
                # Top sources
                f.write("### Top Source IPs\n\n")
                f.write("| IP Address | Count |\n")
                f.write("|------------|-------|\n")
                
                for ip, count in sorted(sources.items(), key=lambda x: x[1], reverse=True)[:10]:
                    f.write(f"| {ip} | {count} |\n")
                    
                # Top destinations
                f.write("\n### Top Destination IPs\n\n")
                f.write("| IP Address | Count |\n")
                f.write("|------------|-------|\n")
                
                for ip, count in sorted(destinations.items(), key=lambda x: x[1], reverse=True)[:10]:
                    f.write(f"| {ip} | {count} |\n")
                    
                # Protocols
                f.write("\n### Protocols\n\n")
                f.write("| Protocol | Count |\n")
                f.write("|----------|-------|\n")
                
                for protocol, count in sorted(protocols.items(), key=lambda x: x[1], reverse=True):
                    f.write(f"| {protocol} | {count} |\n")
                    
                # Allowed vs Denied
                f.write("\n### Traffic Summary\n\n")
                f.write(f"- **Allowed Flows:** {allowed}\n")
                f.write(f"- **Denied Flows:** {denied}\n")
                f.write(f"- **Total Flows:** {len(self.all_network_traffic)}\n")
                
            else:
                f.write("No traffic data was found for this IP address in the specified time range.\n\n")
                
            f.write(f"\n## Conclusion\n\n")
            f.write(f"This report provides an analysis of network traffic and Azure resources related to IP {self.target_ip} ")
            f.write(f"for the period from {self.start_date} to {self.end_date}.\n\n")
            f.write(f"For more detailed information, please refer to the JSON and CSV files in the output directory: {self.output_dir}\n")
            
        print_success(f"Summary report generated: {report_file}")
        
    def run(self) -> None:
        """Run the complete analysis workflow."""
        if not self.login_to_azure():
            return
            
        self.find_resources_by_ip()
        self.find_flow_logs()
        self.query_traffic_data()
        self.generate_report()
        
        print_success(f"\nAnalysis complete! Results saved to: {self.output_dir}")
        print(f"Summary report: {os.path.join(self.output_dir, 'summary_report.md')}")

def main():
    """Main entry point for the script."""
    parser = argparse.ArgumentParser(
        description='Query Azure network traffic logs by IP address',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python query_ip_azure.py 10.0.0.1
  python query_ip_azure.py 192.168.1.100 --days 7
        """
    )
    parser.add_argument('ip_address', help='The IP address to query for')
    parser.add_argument('--days', type=int, default=30, help='Number of days to look back (default: 30)')
    
    args = parser.parse_args()
    
    analyzer = AzureIPTrafficAnalyzer(args.ip_address, args.days)
    analyzer.run()

if __name__ == "__main__":
    main()
